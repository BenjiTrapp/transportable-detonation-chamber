"""The import graph of the system binaries, and the curated Win32 to Nt table under it."""

import json
import os
import re
import subprocess
import threading

import pytest

import binary_graph
import binary_graph_query
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
    # the proof arrives through the file; without a binary graph the process copy is a hint, as the doors of the
    # modules loaded beside the sample are not known
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

# what Task 1 said while no union of a process's doors could be built; each became false the day the binary graph
# could build it, and stays true only for a union that is incomplete
STALE_PROCESS_PHRASES = (
    "never `false`: private memory cannot be attributed",   # docs/api.md, the stubs route
    "never False: its private memory cannot be attributed",  # app.py, api_syscalls_stubs
    "so process mode says only whether the image imports",  # docs/memory.md, the limits of the rule
    "the file is the sample's own, its process memory is not",  # app.py, _syscall_stage_file
    "Until a caller can build that union",                  # syscall_scan.py, find_stubs_in_process
    "so only the file can prove",                           # app.js, over renderSyscallStubs
    "always for a stub in process memory",                  # app.js, the hint over the stub list
    "the search proves nothing there",                      # app.py, _syscall_stage
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
        found += [(os.path.relpath(path, root), phrase) for phrase in STALE_PHRASES + STALE_PROCESS_PHRASES
                  if phrase in text]
    assert found == []


def test_the_stub_list_changed_and_so_did_its_asset_version():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "webui", "templates", "index.html"), encoding="utf-8") as fh:
        html = fh.read()
        assert all(f"app.js?v={v}\"" not in html for v in (136, 137, 138)), "app.js changed, its version did not"


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
        # HashedLength is packed to the documented rule, the name up to but not including its last hyphen, and still
        # ignored on read (Geoff Chappell's "The API Set Schema"; NtUtilsLibrary, NtUtils.ApiSets.pas)
        hashed_len = 2 * len(alias.rpartition("-")[0])
        entries += struct.pack("<6I", 0, alias_at, alias_len, hashed_len, values_at + len(values), len(hosts))
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
    assert (flags, name_len, hashed_len, value_count) == (0, 2 * len("api-y-1-0"), 2 * len("api-y-1"), 2)    # up to, not including, the last hyphen
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
    # a value lost might be the default (value[0]), or an override would move into its place: the wrong module either way
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


def test_an_empty_host_is_an_unreadable_value_and_takes_its_entry_with_it():
    # value[0] is the default host: skipping an empty one would promote an override into the default's place
    data = _api_set_map({"ext-ms-win-gone-l1-1-0": ("",), "api-ms-win-first-l1-1-0": ("", "kernelbase.dll"),
                         "api-ms-win-last-l1-1-0": ("kernelbase.dll", ""), "api-ms-win-ok-l1-1-0": ("kernelbase.dll", "ntdll.dll")})
    assert binary_graph.parse_api_set_map(data) == {"api-ms-win-ok-l1-1-0": ("kernelbase.dll", "ntdll.dll")}


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


def _past_the_declared_size():
    """The two-alias map, then bytes behind its declared Size (the rest of a section): a valid name of the first
    entry's own is out there, so only the declared Size can tell it from a name inside the map."""
    data = _two_aliases()
    late = "api-late-l1-1-0".encode("utf-16-le")
    return data, data + late, len(data), len(late)


def test_an_entry_that_sits_past_the_declared_size_but_inside_the_section_is_dropped():
    _, section, late_at, late_len = _past_the_declared_size()
    parsed = binary_graph.parse_api_set_map(_patched(section, _ENTRY_0 + 4, late_at, late_len))
    assert parsed == {"api-second-l1-1-0": ("ntdll.dll", "kernel32.dll")}
    # the same bytes with the entry pointing inside Size are the whole map: the window is what dropped it
    assert set(binary_graph.parse_api_set_map(section)) == {"api-first-l1-1-0", "api-second-l1-1-0"}


def test_a_value_array_or_a_host_past_the_declared_size_is_dropped_too():
    _, section, late_at, late_len = _past_the_declared_size()
    # the array begins inside Size and ends 10 bytes behind it
    assert set(binary_graph.parse_api_set_map(_patched(section, _ENTRY_0 + 16, late_at - 10, 1))) == {"api-second-l1-1-0"}
    assert set(binary_graph.parse_api_set_map(_patched(section, _VALUES + 12, late_at, late_len))) == {"api-second-l1-1-0"}


def test_a_declared_size_smaller_than_the_data_narrows_the_window_to_it():
    # the packed Size is the length of the map: a map that says it ends earlier loses what lies behind that point
    import struct
    data = _two_aliases()
    second_name_at = struct.unpack_from("<I", data, _ENTRY_1 + 4)[0]
    parsed = binary_graph.parse_api_set_map(_patched(data, 4, second_name_at))
    assert parsed == {"api-first-l1-1-0": ("kernelbase.dll",)}


@pytest.mark.parametrize("size", [0, 0xFFFFFFFF, 10_000_000])
def test_a_declared_size_of_zero_or_larger_than_the_data_falls_back_to_the_data(size):
    # a Size that cannot be right is no reason to read less than there is, but never to read more
    _, section, late_at, late_len = _past_the_declared_size()
    pointing_late = _patched(section, _ENTRY_0 + 4, late_at, late_len)
    assert set(binary_graph.parse_api_set_map(_patched(pointing_late, 4, size))) == {"api-late-l1-1-0", "api-second-l1-1-0"}
    assert len(binary_graph.parse_api_set_map(_patched(_two_aliases(), 4, size))) == 2


# --- following a forwarder chain ----------------------------------------------------------

def test_a_forwarder_is_split_at_its_last_dot_so_an_api_set_name_survives():
    assert binary_graph.split_forwarder("api-ms-win-core-heap-l1-1-0.HeapAlloc") == (
        "api-ms-win-core-heap-l1-1-0.dll", "HeapAlloc")


def test_a_module_name_with_dots_of_its_own_survives_the_split():
    # this is the case that tells the last dot from the first: api-set names are hyphenated and do not
    assert binary_graph.split_forwarder("Windows.Storage.SomeFunction") == ("windows.storage.dll", "SomeFunction")


@pytest.mark.parametrize("raw", ["", "NODOT", ".F", "B.", ".", ".."])
def test_a_string_that_names_no_module_and_function_splits_to_nothing(raw):
    assert binary_graph.split_forwarder(raw) == ("", "")


def test_a_plain_module_forwarder_gains_the_dll_suffix_and_is_lower_cased():
    assert binary_graph.split_forwarder("NTDLL.RtlAllocateHeap") == ("ntdll.dll", "RtlAllocateHeap")


def test_a_forwarder_to_an_ordinal_keeps_the_hash_form():
    assert binary_graph.split_forwarder("NTDLL.#8") == ("ntdll.dll", "#8")


def _bi(name, exports=(), forwarders=None, ordinal_names=None, partial=False):
    return binary_graph.BinaryInfo(name=name, kind="dll", machine="x64", imports={}, exports=tuple(exports),
                                   forwarders=dict(forwarders or {}), ordinal_names=dict(ordinal_names or {}),
                                   partial=partial)


def _graph(*infos):
    return {info.name: info for info in infos}


def _heap_chain():
    # kernel32!HeapAlloc -> api-ms-win-core-heap-l1-1-0 -> kernelbase -> ntdll!RtlAllocateHeap
    binaries = _graph(
        _bi("kernel32.dll", forwarders={"HeapAlloc": "api-ms-win-core-heap-l1-1-0.HeapAlloc"}),
        _bi("kernelbase.dll", forwarders={"HeapAlloc": "NTDLL.RtlAllocateHeap"}),
        _bi("ntdll.dll", exports=["RtlAllocateHeap"]))
    return binaries, {"api-ms-win-core-heap-l1-1-0": ("kernelbase.dll",)}


def test_a_chain_over_an_api_set_ends_at_the_module_that_defines_the_function():
    binaries, api_sets = _heap_chain()
    got = binary_graph.resolve_export(binaries, api_sets, "kernel32.dll", "HeapAlloc")
    assert (got.reason, got.module, got.function) == ("defined", "ntdll.dll", "RtlAllocateHeap")


def test_every_hop_says_whether_it_was_a_forwarder_or_an_api_set():
    binaries, api_sets = _heap_chain()
    got = binary_graph.resolve_export(binaries, api_sets, "kernel32.dll", "HeapAlloc")
    assert got.hops == (
        binary_graph.Hop("api-ms-win-core-heap-l1-1-0.dll", "HeapAlloc", "forwards_to"),
        binary_graph.Hop("kernelbase.dll", "HeapAlloc", "resolves_to"),
        binary_graph.Hop("ntdll.dll", "RtlAllocateHeap", "forwards_to"))


def test_an_import_of_an_api_set_name_resolves_without_a_forwarder_to_start_from():
    binaries, api_sets = _heap_chain()
    got = binary_graph.resolve_export(binaries, api_sets, "API-MS-WIN-CORE-HEAP-L1-1-0.dll", "HeapAlloc")
    assert (got.reason, got.module, got.function) == ("defined", "ntdll.dll", "RtlAllocateHeap")
    assert got.hops[0] == binary_graph.Hop("kernelbase.dll", "HeapAlloc", "resolves_to")


def test_a_function_that_is_defined_where_it_is_asked_for_has_no_hops():
    got = binary_graph.resolve_export(_graph(_bi("ntdll.dll", exports=["NtClose"])), {}, "NTDLL.DLL", "NtClose")
    assert got == binary_graph.Resolution(hops=(), module="ntdll.dll", function="NtClose", reason="defined")


def test_an_api_set_tries_its_host_modules_in_order_until_one_defines_the_function():
    binaries = _graph(_bi("first.dll", exports=["Other"]), _bi("gone-from-graph-is-skipped.dll"),
                      _bi("second.dll", exports=["Wanted"]), _bi("third.dll", exports=["Wanted"]))
    api_sets = {"api-x-l1-1-0": ("first.dll", "not-in-graph.dll", "second.dll", "third.dll")}
    got = binary_graph.resolve_export(binaries, api_sets, "api-x-l1-1-0.dll", "Wanted")
    assert (got.reason, got.module) == ("defined", "second.dll")
    assert got.hops == (binary_graph.Hop("second.dll", "Wanted", "resolves_to"),)


def test_a_function_no_module_defines_ends_as_missing():
    binaries, api_sets = _heap_chain()
    got = binary_graph.resolve_export(binaries, api_sets, "kernel32.dll", "NoSuchFunction")
    assert (got.reason, got.module, got.function, got.hops) == ("missing", None, None, ())
    # the chain walked as far as it went is kept: the last hop is where it died
    broken = _graph(_bi("kernel32.dll", forwarders={"F": "GONE.F"}))
    got = binary_graph.resolve_export(broken, {}, "kernel32.dll", "F")
    assert (got.reason, got.module, got.function) == ("missing", None, None)
    assert got.hops == (binary_graph.Hop("gone.dll", "F", "forwards_to"),)


def test_a_module_that_is_not_in_the_graph_is_missing_not_an_error():
    got = binary_graph.resolve_export({}, {}, "kernel32.dll", "F")
    assert (got.reason, got.hops) == ("missing", ())


def test_an_api_set_with_no_entry_in_the_map_ends_as_unresolved_api_set():
    binaries = _graph(_bi("kernel32.dll", forwarders={"F": "api-ms-win-core-nowhere-l1-1-0.F"}))
    got = binary_graph.resolve_export(binaries, {}, "kernel32.dll", "F")
    assert (got.reason, got.module, got.function) == ("unresolved-api-set", None, None)
    assert got.hops == (binary_graph.Hop("api-ms-win-core-nowhere-l1-1-0.dll", "F", "forwards_to"),)
    # an ext-ms- name is an api set too, whatever the map holds
    assert binary_graph.resolve_export(binaries, {"other": ("a.dll",)}, "ext-ms-win-x-l1-1-0.dll", "F"
                                       ).reason == "unresolved-api-set"


def test_an_api_set_whose_hosts_do_not_define_the_function_is_missing_not_unresolved():
    # the map knew the alias: it is System32 that does not offer the function
    binaries = _graph(_bi("host.dll", exports=["Other"]))
    got = binary_graph.resolve_export(binaries, {"api-x-l1-1-0": ("host.dll",)}, "api-x-l1-1-0.dll", "Wanted")
    assert got.reason == "missing"


def test_a_forwarder_to_an_ordinal_resolves_through_the_target_ordinal_names():
    binaries = _graph(_bi("a.dll", forwarders={"F": "NTDLL.#8"}),
                      _bi("ntdll.dll", exports=["RtlFoo"], ordinal_names={8: "RtlFoo"}))
    got = binary_graph.resolve_export(binaries, {}, "a.dll", "F")
    assert (got.reason, got.module, got.function) == ("defined", "ntdll.dll", "RtlFoo")
    assert got.hops == (binary_graph.Hop("ntdll.dll", "#8", "forwards_to"),)


def test_a_forwarder_to_a_nameless_export_is_defined_under_its_hash_name():
    binaries = _graph(_bi("a.dll", forwarders={"F": "B.#5"}), _bi("b.dll", exports=["#5"]))
    got = binary_graph.resolve_export(binaries, {}, "a.dll", "F")
    assert (got.reason, got.module, got.function) == ("defined", "b.dll", "#5")


def test_a_forwarder_to_an_ordinal_the_target_does_not_offer_is_missing():
    binaries = _graph(_bi("a.dll", forwarders={"F": "B.#9"}), _bi("b.dll", exports=["X"], ordinal_names={8: "X"}))
    assert binary_graph.resolve_export(binaries, {}, "a.dll", "F").reason == "missing"


def test_an_ordinal_that_names_a_forwarder_keeps_following_the_chain():
    binaries = _graph(_bi("a.dll", forwarders={"F": "B.#3"}),
                      _bi("b.dll", forwarders={"G": "C.H"}, ordinal_names={3: "G"}),
                      _bi("c.dll", exports=["H"]))
    got = binary_graph.resolve_export(binaries, {}, "a.dll", "F")
    assert (got.reason, got.module, got.function) == ("defined", "c.dll", "H")
    assert [h.function for h in got.hops] == ["#3", "H"]


@pytest.mark.parametrize("raw", ["", "NODOT", ".F", "B.", ".", "..", "B.#x", "B.#", "B.#" + "9" * 5000])
def test_a_malformed_forwarder_ends_as_missing_and_raises_nothing(raw):
    binaries = _graph(_bi("a.dll", forwarders={"F": raw}), _bi("b.dll", exports=["X"]))
    got = binary_graph.resolve_export(binaries, {}, "a.dll", "F")
    assert (got.reason, got.module, got.function) == ("missing", None, None)


def test_a_chain_that_dies_in_a_partial_binary_is_missing_and_says_its_answer_is_not_certain():
    # pefile cut that binary's tables short: "missing" stays the reason, `partial` is what says it may be wrong
    binaries = _graph(_bi("a.dll", forwarders={"F": "B.F"}), _bi("b.dll", partial=True))
    got = binary_graph.resolve_export(binaries, {}, "a.dll", "F")
    assert (got.reason, got.partial) == ("missing", True)


def test_a_chain_through_complete_binaries_is_not_marked_partial():
    binaries, api_sets = _heap_chain()
    for start in ("kernel32.dll", "api-ms-win-core-heap-l1-1-0.dll"):
        assert binary_graph.resolve_export(binaries, api_sets, start, "HeapAlloc").partial is False
    assert binary_graph.resolve_export(binaries, api_sets, "kernel32.dll", "Nope").partial is False
    assert binary_graph.resolve_export({}, {}, "x.dll", "F").partial is False


def test_a_partial_binary_anywhere_on_the_chain_marks_it_not_only_the_one_it_died_in():
    # the cut-short table is the middle one, the chain still ends cleanly in a complete module
    binaries = _graph(_bi("a.dll", forwarders={"F": "B.F"}), _bi("b.dll", forwarders={"F": "C.F"}, partial=True),
                      _bi("c.dll", exports=["F"]))
    got = binary_graph.resolve_export(binaries, {}, "a.dll", "F")
    assert (got.reason, got.partial) == ("defined", True)
    # and the other way round: the chain starts in the partial one
    assert binary_graph.resolve_export(_graph(_bi("a.dll", exports=["F"], partial=True)), {}, "a.dll", "F").partial


def test_an_api_set_host_that_was_passed_over_and_is_partial_marks_the_chain():
    # first.dll might have defined it had its export table not been cut short: the host chosen is not certain
    binaries = _graph(_bi("first.dll", partial=True), _bi("second.dll", exports=["Wanted"]))
    got = binary_graph.resolve_export(binaries, {"api-x-l1-1-0": ("first.dll", "second.dll")}, "api-x-l1-1-0.dll", "Wanted")
    assert (got.reason, got.module, got.partial) == ("defined", "second.dll", True)
    # a host that is never reached does not
    binaries = _graph(_bi("first.dll", exports=["Wanted"]), _bi("second.dll", partial=True))
    got = binary_graph.resolve_export(binaries, {"api-x-l1-1-0": ("first.dll", "second.dll")}, "api-x-l1-1-0.dll", "Wanted")
    assert (got.reason, got.partial) == ("defined", False)


def test_every_negative_reason_carries_the_partial_flag_of_its_chain():
    ring = _graph(_bi("a.dll", forwarders={"F": "B.F"}, partial=True), _bi("b.dll", forwarders={"F": "A.F"}))
    assert binary_graph.resolve_export(ring, {}, "a.dll", "F").partial is True
    lost = _graph(_bi("a.dll", forwarders={"F": "api-nowhere-l1-1-0.F"}, partial=True))
    got = binary_graph.resolve_export(lost, {}, "a.dll", "F")
    assert (got.reason, got.partial) == ("unresolved-api-set", True)
    long = _long_chain(binary_graph.MAX_HOPS + 4)
    long["m3.dll"] = _bi("m3.dll", forwarders={"F": "M4.F"}, partial=True)
    got = binary_graph.resolve_export(long, {}, "m0.dll", "F")
    assert (got.reason, got.partial) == ("too-many-hops", True)


def test_resolve_all_carries_the_partial_flag_too():
    binaries = _graph(_bi("a.dll", forwarders={"F": "B.F"}), _bi("b.dll", partial=True))
    assert binary_graph.resolve_all(binaries, {})[("a.dll", "F")].partial is True


def test_resolving_all_forwarders_answers_each_module_and_function_once():
    binaries, api_sets = _heap_chain()
    binaries["kernel32.dll"] = _bi("kernel32.dll", exports=["Own"], forwarders={
        "HeapAlloc": "api-ms-win-core-heap-l1-1-0.HeapAlloc", "Lost": "GONE.Lost"})
    got = binary_graph.resolve_all(binaries, api_sets)
    assert set(got) == {("kernel32.dll", "HeapAlloc"), ("kernel32.dll", "Lost"), ("kernelbase.dll", "HeapAlloc")}
    assert got[("kernel32.dll", "HeapAlloc")] == binary_graph.resolve_export(binaries, api_sets, "kernel32.dll", "HeapAlloc")
    assert got[("kernel32.dll", "Lost")].reason == "missing"
    assert got[("kernelbase.dll", "HeapAlloc")].module == "ntdll.dll"


def test_a_forwarder_that_points_back_to_itself_ends_as_a_cycle():
    binaries = _graph(_bi("a.dll", forwarders={"F": "A.F"}))
    got = binary_graph.resolve_export(binaries, {}, "a.dll", "F")
    assert (got.reason, got.module, got.function) == ("cycle", None, None)
    assert got.hops == (binary_graph.Hop("a.dll", "F", "forwards_to"),)


def test_a_forwarder_ring_over_three_modules_ends_as_a_cycle_and_names_its_hops():
    binaries = _graph(_bi("a.dll", forwarders={"F": "B.F"}), _bi("b.dll", forwarders={"F": "C.F"}),
                      _bi("c.dll", forwarders={"F": "A.F"}))
    got = binary_graph.resolve_export(binaries, {}, "a.dll", "F")
    assert got.reason == "cycle"
    assert [h.module for h in got.hops] == ["b.dll", "c.dll", "a.dll"]    # the last is the one that closes the ring


def test_a_ring_through_an_api_set_is_a_cycle_too():
    binaries = _graph(_bi("host.dll", forwarders={"F": "api-x-l1-1-0.F"}))
    got = binary_graph.resolve_export(binaries, {"api-x-l1-1-0": ("host.dll",)}, "host.dll", "F")
    assert got.reason == "cycle"
    assert [h.via for h in got.hops] == ["forwards_to", "resolves_to"]


def _long_chain(length):
    # m0 -> m1 -> ... -> m<length>, every pair distinct: nothing repeats, so only the hop cap can stop it
    infos = [_bi(f"m{i}.dll", forwarders={"F": f"M{i + 1}.F"}) for i in range(length)]
    infos.append(_bi(f"m{length}.dll", exports=["F"]))
    return _graph(*infos)


def test_a_chain_longer_than_max_hops_ends_as_too_many_hops():
    got = binary_graph.resolve_export(_long_chain(binary_graph.MAX_HOPS + 4), {}, "m0.dll", "F")
    assert (got.reason, got.module, got.function) == ("too-many-hops", None, None)
    assert len(got.hops) == binary_graph.MAX_HOPS


def test_a_chain_of_exactly_max_hops_still_resolves():
    got = binary_graph.resolve_export(_long_chain(binary_graph.MAX_HOPS), {}, "m0.dll", "F")
    assert (got.reason, len(got.hops)) == ("defined", binary_graph.MAX_HOPS)


def test_a_ring_longer_than_max_hops_is_still_named_a_cycle():
    # the hop cap is a policy on chain length, not the ring detector: a ring that closes only after the cap is a ring
    ring = binary_graph.MAX_HOPS * 2
    infos = [_bi(f"m{i}.dll", forwarders={"F": f"M{(i + 1) % ring}.F"}) for i in range(ring)]
    got = binary_graph.resolve_export(_graph(*infos), {}, "m0.dll", "F")
    assert (got.reason, len(got.hops)) == ("cycle", ring)


def test_resolving_never_raises_on_an_odd_start():
    binaries = _graph(_bi("a.dll", forwarders={"F": "A.F"}))
    for module, function in [("", ""), ("a.dll", ""), ("A.DLL", "#"), ("a.dll", "#" + "9" * 5000), ("nope", "F")]:
        assert binary_graph.resolve_export(binaries, {}, module, function).reason in ("missing", "cycle")


def test_the_same_module_visited_for_another_function_is_not_a_cycle():
    # a!F -> b!X -> a!G: `a` twice, never the same (module, function) twice
    binaries = _graph(_bi("a.dll", exports=["G"], forwarders={"F": "B.X"}), _bi("b.dll", forwarders={"X": "A.G"}))
    got = binary_graph.resolve_export(binaries, {}, "a.dll", "F")
    assert (got.reason, got.module, got.function) == ("defined", "a.dll", "G")
    assert [h.module for h in got.hops] == ["b.dll", "a.dll"]


# the loader hashes an api-set name up to but not including its last hyphen, so ...-l1-1-0 and ...-l1-1-1 are one entry
def test_an_api_set_version_the_map_lacks_resolves_through_its_family():
    binaries = _graph(_bi("kernel32.dll", forwarders={"F": "api-ms-win-core-heap-l1-1-1.F"}),
                      _bi("kernelbase.dll", exports=["F"]))
    api_sets = {"api-ms-win-core-heap-l1-1-0": ("kernelbase.dll",)}
    got = binary_graph.resolve_export(binaries, api_sets, "kernel32.dll", "F")
    assert (got.reason, got.module) == ("defined", "kernelbase.dll")
    assert got.hops[0] == binary_graph.Hop("api-ms-win-core-heap-l1-1-1.dll", "F", "forwards_to")


def test_an_api_set_name_the_map_holds_exactly_is_not_taken_from_a_neighbouring_version():
    binaries = _graph(_bi("old.dll", exports=["F"]), _bi("new.dll", exports=["F"]))
    api_sets = {"api-x-l1-1-0": ("old.dll",), "api-x-l1-1-1": ("new.dll",)}
    assert binary_graph.resolve_export(binaries, api_sets, "api-x-l1-1-1.dll", "F").module == "new.dll"
    assert binary_graph.resolve_export(binaries, api_sets, "api-x-l1-1-0.dll", "F").module == "old.dll"


def test_an_api_set_of_another_family_does_not_fall_back_to_a_neighbour():
    api_sets = {"api-x-l1-1-0": ("old.dll",)}
    binaries = _graph(_bi("old.dll", exports=["F"]))
    for name in ("api-x-l1-2-0.dll", "api-y-l1-1-0.dll", "api-x.dll", "api-.dll"):
        assert binary_graph.resolve_export(binaries, api_sets, name, "F").reason == "unresolved-api-set", name


def test_a_module_that_is_not_an_api_set_never_falls_back_to_a_family():
    binaries = _graph(_bi("old.dll", exports=["F"]))
    got = binary_graph.resolve_export(binaries, {"foo-1-0": ("old.dll",)}, "foo-1-1.dll", "F")
    assert got.reason == "missing"


class _CountingTuple(tuple):
    scans = 0

    def __iter__(self):
        type(self).scans += 1
        return super().__iter__()

    def __contains__(self, item):
        type(self).scans += 1
        return super().__contains__(item)


def test_the_exports_of_a_binary_are_scanned_once_however_many_chains_end_in_it():
    _CountingTuple.scans = 0
    definer = _bi("ntdll.dll")
    definer = binary_graph.BinaryInfo(**{**definer.__dict__, "exports": _CountingTuple(f"Rtl{i}" for i in range(50))})
    importer = _bi("kernelbase.dll", forwarders={f"F{i}": f"NTDLL.Rtl{i}" for i in range(50)})
    got = binary_graph.resolve_all(_graph(definer, importer), {})
    assert {r.reason for r in got.values()} == {"defined"}
    assert _CountingTuple.scans == 1


# --- the cache: build, stamp, load -----------------------------------------------------------

def _system32(tmp_path):
    """A small System32: kernel32 forwards HeapAlloc over an api set to kernelbase, which forwards it to ntdll."""
    root = tmp_path / "System32"
    root.mkdir()
    ntdll = ("ntdll.dll", dict(dll=True, exports=("RtlAllocateHeap", "NtClose")))
    kernelbase = ("kernelbase.dll", dict(dll=True, exports=("CreateFileW",), imports=(("ntdll.dll", ("NtClose",)),),
                                         forwarders=(("HeapAlloc", "NTDLL.RtlAllocateHeap"),)))
    kernel32 = ("kernel32.dll", dict(dll=True, imports=(("ntdll.dll", ("NtClose", "RtlAllocateHeap")),
                                                         ("kernelbase.dll", ("CreateFileW",))),
                                     forwarders=(("HeapAlloc", "api-ms-win-core-heap-l1-1-0.HeapAlloc"),)))
    tool = ("tool.exe", dict(imports=(("kernel32.dll", ("CreateFileW", "HeapAlloc", "CloseHandle")),
                                      ("ntdll.dll", ("NtClose",)))))
    other = ("other.exe", dict(imports=(("kernel32.dll", ("CreateFileW",)),)))
    for name, pe in (ntdll, kernelbase, kernel32, tool, other):
        (root / name).write_bytes(make_pe(**pe))
    (root / "readme.dll").write_bytes(b"not a pe at all")
    mapping = {"api-ms-win-core-heap-l1-1-0": ("kernelbase.dll",)}
    (root / "apisetschema.dll").write_bytes(make_pe(dll=True, sections=((".apiset", _api_set_map(mapping)),)))
    return root, mapping


def _build(tmp_path, build="26220.5770", arch="arm64"):
    root, mapping = _system32(tmp_path)
    graph = binary_graph.build_graph(str(root), str(root / "apisetschema.dll"), build, arch)
    return graph, mapping


def test_the_graph_holds_every_binary_its_api_sets_and_the_resolved_forwarders(tmp_path):
    graph, mapping = _build(tmp_path)
    assert (graph.build, graph.arch) == ("26220.5770", "arm64")
    assert set(graph.binaries) == {"ntdll.dll", "kernelbase.dll", "kernel32.dll", "tool.exe", "other.exe",
                                   "apisetschema.dll"}
    assert all(key == info.name for key, info in graph.binaries.items())
    assert graph.binaries["kernelbase.dll"].forwarders == {"HeapAlloc": "NTDLL.RtlAllocateHeap"}
    assert graph.api_sets == mapping
    heap = graph.resolved[("kernel32.dll", "HeapAlloc")]
    assert (heap.reason, heap.module, heap.function) == ("defined", "ntdll.dll", "RtlAllocateHeap")
    assert [h.module for h in heap.hops] == ["api-ms-win-core-heap-l1-1-0.dll", "kernelbase.dll", "ntdll.dll"]
    assert set(graph.resolved) == {("kernel32.dll", "HeapAlloc"), ("kernelbase.dll", "HeapAlloc")}
    assert graph.skipped == (("readme.dll", "not a PE"),)
    assert isinstance(graph.skipped, tuple)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", graph.created)


def test_a_graph_without_a_schema_dll_is_degraded_not_broken(tmp_path):
    root, _ = _system32(tmp_path)
    graph = binary_graph.build_graph(str(root), str(root / "missing.dll"), "1.1", "x64")
    assert graph.api_sets == {}
    assert graph.resolved[("kernel32.dll", "HeapAlloc")].reason == "unresolved-api-set"
    assert "ntdll.dll" in graph.binaries


def test_the_in_degree_of_a_module_counts_the_binaries_that_import_it_not_the_functions(tmp_path):
    graph, _ = _build(tmp_path)
    # tool.exe imports three functions of kernel32 and other.exe one: two binaries, not four functions
    assert graph.in_degree["kernel32.dll"] == 2
    assert graph.in_degree["ntdll.dll"] == 3            # kernelbase, kernel32, tool
    assert graph.in_degree["kernelbase.dll"] == 1
    assert "tool.exe" not in graph.in_degree            # nothing imports it


def test_a_module_that_is_not_in_the_graph_still_counts_its_importers(tmp_path):
    root = tmp_path / "System32"
    root.mkdir()
    for name in ("a.exe", "b.exe"):
        (root / name).write_bytes(make_pe(imports=(("vanished.dll", ("One", "Two")),), delay=(("vanished.dll", ("Three",)),)))
    graph = binary_graph.build_graph(str(root), str(root / "none.dll"), "1.1", "x64")
    assert graph.in_degree == {"vanished.dll": 2}       # a delay-load of the same module is not a third importer


def _strange_graph():
    """Every field of every record set to something a careless round trip would lose."""
    info = binary_graph.BinaryInfo(
        name="odd.dll", kind="dll", machine="other", imports={"a.dll": ("#7", 'Q"uote\\', "\ufffd"), "b.dll": ()},
        exports=("#3", "Zed", "alpha"), forwarders={"#3": "NTDLL.#9", "Fwd": "api-ms-win-x-l1-1-0.Fn"},
        ordinal_names={1: "alpha", 65535: "Zed"}, partial=True)
    plain = binary_graph.BinaryInfo(name="plain.exe", kind="exe", machine="x64", imports={}, exports=(),
                                    forwarders={}, ordinal_names={}, partial=False)
    hops = (binary_graph.Hop("api-ms-win-x-l1-1-0.dll", "Fn", "resolves_to"), binary_graph.Hop("b.dll", "Fn", "forwards_to"))
    resolved = {("odd.dll", "Fwd"): binary_graph.Resolution(hops, "b.dll", "Fn", "defined", True),
                ("odd.dll", "#3"): binary_graph.Resolution((), None, None, "missing", False),
                ("odd.dll", "x"): binary_graph.Resolution(hops[:1], None, None, "cycle", True)}
    return binary_graph.Graph(
        build="26220.5770", arch="arm64", created="2026-11-23T10:00:00Z",
        binaries={"odd.dll": info, "plain.exe": plain}, api_sets={"api-ms-win-x-l1-1-0": ("b.dll", "c.dll"), "e": ()},
        resolved=resolved, in_degree={"a.dll": 1, "b.dll": 0, "gone.dll": 12},
        skipped=(("x.dll", "not a PE"), ("y.exe", "malformed")))


def _assert_same_graph(got, want):
    for field in ("build", "arch", "created", "api_sets", "in_degree", "skipped"):
        assert getattr(got, field) == getattr(want, field), field
        assert type(getattr(got, field)) is type(getattr(want, field)), field
    assert list(got.binaries) == list(want.binaries)
    for key, info in want.binaries.items():
        loaded = got.binaries[key]
        for field in ("name", "kind", "machine", "imports", "exports", "forwarders", "ordinal_names", "partial"):
            assert getattr(loaded, field) == getattr(info, field), (key, field)
            assert type(getattr(loaded, field)) is type(getattr(info, field)), (key, field)
        assert all(type(k) is int for k in loaded.ordinal_names)
        assert all(type(v) is tuple for v in loaded.imports.values())
    assert set(got.resolved) == set(want.resolved)
    for key, res in want.resolved.items():
        loaded = got.resolved[key]
        assert (loaded.module, loaded.function, loaded.reason, loaded.partial) == (res.module, res.function, res.reason, res.partial), key
        assert type(loaded.hops) is tuple and loaded.hops == res.hops, key
        assert all(type(h) is binary_graph.Hop for h in loaded.hops)
    assert got == want


def test_a_graph_survives_save_and_load_unchanged(tmp_path):
    want = _strange_graph()
    path = str(tmp_path / "cache.json")
    binary_graph.save_graph(want, path)
    _assert_same_graph(binary_graph.load_graph(path, "26220.5770", "arm64"), want)


def test_a_built_graph_survives_save_and_load_unchanged(tmp_path):
    want, _ = _build(tmp_path)
    path = str(tmp_path / "cache.json")
    binary_graph.save_graph(want, path)
    _assert_same_graph(binary_graph.load_graph(path, want.build, want.arch), want)


def test_the_stamp_is_the_head_of_the_file(tmp_path):
    path = tmp_path / "cache.json"
    binary_graph.save_graph(_strange_graph(), str(path))
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert list(doc)[:4] == ["format", "build", "arch", "created"]
    assert (doc["build"], doc["arch"], doc["created"]) == ("26220.5770", "arm64", "2026-11-23T10:00:00Z")


def test_saving_leaves_no_half_written_file_beside_the_cache(tmp_path):
    path = tmp_path / "cache.json"
    binary_graph.save_graph(_strange_graph(), str(path))
    assert os.listdir(tmp_path) == ["cache.json"]
    path.write_text("old")
    unwritable = _strange_graph()
    object.__setattr__(unwritable, "in_degree", {"x": object()})        # json cannot encode this
    with pytest.raises(TypeError):
        binary_graph.save_graph(unwritable, str(path))
    assert path.read_text() == "old" and os.listdir(tmp_path) == ["cache.json"]


def test_a_save_that_fails_on_the_way_leaves_the_earlier_cache_whole(tmp_path, monkeypatch):
    path = tmp_path / "cache.json"
    path.write_text("old")

    def refuse(*args):
        raise OSError("the disk went away")

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(OSError):
        binary_graph.save_graph(_strange_graph(), str(path))
    assert path.read_text() == "old" and os.listdir(tmp_path) == ["cache.json"]


def test_a_cache_is_flushed_to_disk_before_it_takes_its_name(tmp_path, monkeypatch):
    # os.replace is atomic, but without an fsync first a power loss can leave the renamed file zero-filled or cut short
    events = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(os, "fsync", lambda fd: (events.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(os, "replace", lambda a, b: (events.append("replace"), real_replace(a, b))[1])
    binary_graph.save_graph(_strange_graph(), str(tmp_path / "cache.json"))
    assert events == ["fsync", "replace"]


def test_two_saves_at_once_write_beside_the_cache_under_names_of_their_own(tmp_path, monkeypatch):
    sources = []
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (sources.append(a), real_replace(a, b))[1])
    path = str(tmp_path / "cache.json")
    binary_graph.save_graph(_strange_graph(), path)
    binary_graph.save_graph(_strange_graph(), path)
    assert len(set(sources)) == 2 and all(src != path + ".tmp" for src in sources)
    assert os.listdir(tmp_path) == ["cache.json"]


def test_a_save_in_progress_is_left_alone_and_one_that_a_killed_build_left_behind_is_removed(tmp_path):
    import time
    path = tmp_path / "cache.json"
    active = tmp_path / "cache.json.0123456789abcdef.tmp"
    killed = tmp_path / "cache.json.fedcba9876543210.tmp"
    unrelated = tmp_path / "other.json.0123456789abcdef.tmp"
    for leftover in (active, killed, unrelated):
        leftover.write_text("half")
    long_ago = time.time() - 3 * 3600
    os.utime(killed, (long_ago, long_ago))
    os.utime(unrelated, (long_ago, long_ago))
    binary_graph.save_graph(_strange_graph(), str(path))
    assert sorted(os.listdir(tmp_path)) == sorted(["cache.json", active.name, unrelated.name])
    assert active.read_text() == "half"             # a build that is writing right now is not this one's to delete


def test_a_cache_that_is_valid_json_but_cut_short_is_refused_not_kept(tmp_path):
    text = _saved(tmp_path, _strange_graph())
    doc = json.loads(text)
    for name, damaged in (("cut", text[:len(text) // 2]), ("zero-filled", "\0" * len(text)),
                          ("stamp only", json.dumps({k: doc[k] for k in ("format", "build", "arch", "created")})),
                          ("empty", "")):
        path = tmp_path / "cache.json"
        path.write_text(damaged, encoding="utf-8")
        with pytest.raises(binary_graph.CacheMismatch) as e:
            binary_graph.load_graph(str(path), "26220.5770", "arm64")
        assert e.value.reason == "malformed", name


def test_the_cli_check_accepts_a_whole_cache_and_refuses_a_cut_one(tmp_path, capsys):
    root, _ = _system32(tmp_path)
    out = tmp_path / "out"
    args = ["--out", str(out), "--build", "1.1", "--arch", "x64"]
    assert binary_graph.main(args + ["--system32", str(root)]) == 0
    capsys.readouterr()
    assert binary_graph.main(args + ["--check"]) == 0
    assert "binaries: 6" in capsys.readouterr().out.splitlines()
    cache = out / binary_graph.cache_name("1.1", "x64")
    cache.write_bytes(cache.read_bytes()[:-40])
    assert binary_graph.main(args + ["--check"]) == 1
    assert "malformed" in capsys.readouterr().err
    cache.unlink()
    assert binary_graph.main(args + ["--check"]) == 1                    # no cache is not a good one either
    assert binary_graph.main(["--out", str(out), "--build", "9.9", "--arch", "x64", "--check"]) == 1


def test_the_cli_check_refuses_a_cache_stamped_for_another_build(tmp_path, capsys):
    graph = _strange_graph()
    binary_graph.save_graph(graph, str(tmp_path / binary_graph.cache_name("26220.9999", "arm64")))     # a stamp 5770 on a 9999 name
    assert binary_graph.main(["--out", str(tmp_path), "--build", "26220.9999", "--arch", "arm64", "--check"]) == 1
    assert "other build" in capsys.readouterr().err


def test_loading_a_cache_of_another_build_is_refused_with_the_build_it_holds(tmp_path):
    path = str(tmp_path / "cache.json")
    binary_graph.save_graph(_strange_graph(), path)
    with pytest.raises(binary_graph.CacheMismatch) as e:
        binary_graph.load_graph(path, "26220.9999", "arm64")
    assert "26220.5770" in str(e.value) and "26220.9999" in str(e.value)
    assert (e.value.reason, e.value.held_build, e.value.held_arch) == ("other build", "26220.5770", "arm64")


def test_loading_a_cache_of_another_architecture_is_refused(tmp_path):
    path = str(tmp_path / "cache.json")
    binary_graph.save_graph(_strange_graph(), path)
    with pytest.raises(binary_graph.CacheMismatch) as e:
        binary_graph.load_graph(path, "26220.5770", "x64")
    assert e.value.reason == "other architecture" and e.value.held_arch == "arm64" and "arm64" in str(e.value)


def test_a_cache_of_another_build_is_refused_before_its_body_is_read(tmp_path):
    path = tmp_path / "cache.json"
    doc = json.loads(_saved(tmp_path, _strange_graph()))
    doc["binaries"] = "this would not decode"
    path.write_text(json.dumps(doc))
    with pytest.raises(binary_graph.CacheMismatch) as e:
        binary_graph.load_graph(str(path), "1.1", "arm64")
    assert e.value.reason == "other build"


def _saved(tmp_path, graph, name="saved.json"):
    path = tmp_path / name
    binary_graph.save_graph(graph, str(path))
    return path.read_text(encoding="utf-8")


def test_a_cache_whose_json_is_truncated_is_refused_and_does_not_raise_json_errors(tmp_path):
    text = _saved(tmp_path, _strange_graph())
    for cut in sorted({0, 1, 10, len(text) // 3, len(text) // 2, len(text) - 2, len(text) - 1}):
        path = tmp_path / "cut.json"
        path.write_text(text[:cut], encoding="utf-8")
        with pytest.raises(binary_graph.CacheMismatch) as e:
            binary_graph.load_graph(str(path), "26220.5770", "arm64")
        assert e.value.reason == "malformed", cut


@pytest.mark.parametrize("content", [b"", b"not json", b"\xff\xfe\x00garbage", b"[]", b"null", b"42", b'"text"',
                                     b"[" * 100000, b"{}", b'{"format": 1}', b'{"format": 2, "build": "26220.5770", "arch": "arm64"}'])
def test_a_file_that_is_not_a_cache_is_refused_with_a_reason(tmp_path, content):
    path = tmp_path / "cache.json"
    path.write_bytes(content)
    with pytest.raises(binary_graph.CacheMismatch) as e:
        binary_graph.load_graph(str(path), "26220.5770", "arm64")
    assert e.value.reason in ("malformed", "unknown format")


def test_a_cache_of_a_format_this_code_does_not_know_is_refused(tmp_path):
    doc = json.loads(_saved(tmp_path, _strange_graph()))
    doc["format"] = 99
    path = tmp_path / "cache.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(binary_graph.CacheMismatch) as e:
        binary_graph.load_graph(str(path), "26220.5770", "arm64")
    assert e.value.reason == "unknown format"


def _damaged(tmp_path, damage):
    doc = json.loads(_saved(tmp_path, _strange_graph()))
    damage(doc)
    path = tmp_path / "damaged.json"
    path.write_text(json.dumps(doc))
    return str(path)


@pytest.mark.parametrize("damage", [
    lambda d: d.pop("binaries"), lambda d: d.pop("api_sets"), lambda d: d.pop("resolved"),
    lambda d: d.pop("in_degree"), lambda d: d.pop("skipped"), lambda d: d.pop("created"),
    lambda d: d.update(binaries=[]), lambda d: d.update(binaries=7), lambda d: d.update(api_sets=["x"]),
    lambda d: d.update(resolved={}), lambda d: d.update(resolved=[1]), lambda d: d.update(skipped=[["only one"]]),
    lambda d: d.update(in_degree={"a.dll": "three"}), lambda d: d.update(in_degree={"a.dll": True}),
    lambda d: d.update(created=5), lambda d: d["binaries"]["odd.dll"].pop("partial"),
    lambda d: d["binaries"]["odd.dll"].update(partial="yes"), lambda d: d["binaries"]["odd.dll"].update(imports={"a.dll": "abc"}),
    lambda d: d["binaries"]["odd.dll"].update(exports="abc"), lambda d: d["binaries"]["odd.dll"].update(ordinal_names={"x": "y"}),
    lambda d: d["binaries"]["odd.dll"].update(forwarders={"a": 1}), lambda d: d["resolved"][0].update(hops=[["a", "b"]]),
    lambda d: d["resolved"][0].pop("reason"), lambda d: d["resolved"][0].update(partial=None),
], ids=range(24))
def test_a_cache_of_the_right_stamp_but_the_wrong_shape_is_refused_as_malformed(tmp_path, damage):
    with pytest.raises(binary_graph.CacheMismatch) as e:
        binary_graph.load_graph(_damaged(tmp_path, damage), "26220.5770", "arm64")
    assert e.value.reason == "malformed"


def test_a_missing_cache_is_refused_not_raised_as_an_os_error(tmp_path):
    with pytest.raises(binary_graph.CacheMismatch) as e:
        binary_graph.load_graph(str(tmp_path / "none.json"), "1.1", "x64")
    assert e.value.reason == "unreadable"
    with pytest.raises(binary_graph.CacheMismatch):
        binary_graph.load_graph(str(tmp_path), "1.1", "x64")                   # a directory is not a cache


def test_the_cache_name_keeps_it_apart_from_a_syscall_baseline_in_the_same_directory(tmp_path):
    assert binary_graph.cache_name("26220.5770", "arm64") == "binary-graph-26220.5770-arm64.json"
    assert syscall_baseline.parse_baseline_name(binary_graph.cache_name("26220.5770", "arm64")) is None
    assert syscall_baseline.parse_baseline_name(binary_graph.cache_name("26220.5770", "x64")) is None
    (tmp_path / "ntsleuth-26220.5770-arm64.json").write_text("{}")
    assert binary_graph.find_cache(str(tmp_path), "26220.5770", "arm64") is None      # a baseline is no cache
    (tmp_path / binary_graph.cache_name("26220.5770", "arm64")).write_text("{}")
    only_cache = tmp_path / "only-cache"
    only_cache.mkdir()
    (only_cache / binary_graph.cache_name("26220.5770", "arm64")).write_text("{}")
    assert syscall_baseline.find_baseline(str(only_cache), "26220.5770", "arm64") is None     # nor a cache a baseline
    assert binary_graph.find_cache(str(tmp_path), "26220.5770", "arm64") == str(
        tmp_path / "binary-graph-26220.5770-arm64.json")
    assert binary_graph.find_cache(str(tmp_path), "26220.5770", "x64") is None
    assert binary_graph.find_cache(str(tmp_path), "26220.0000", "arm64") is None
    assert binary_graph.find_cache(str(tmp_path / "nowhere"), "26220.5770", "arm64") is None


@pytest.mark.parametrize("build,arch", [("../x", "arm64"), ("1.1", "../arm64"), ("", "x64"), ("1.1", ""),
                                        ("1/1", "x64"), ("1.1", "x64\n"), ("1.1\n", "x64"), ("a b", "x64")])
def test_a_build_or_architecture_that_could_name_another_path_gives_no_cache_name(tmp_path, build, arch):
    with pytest.raises(ValueError):
        binary_graph.cache_name(build, arch)
    assert binary_graph.find_cache(str(tmp_path), build, arch) is None


# --- the command line the provisioning script calls --------------------------------------------

def test_the_cli_writes_a_cache_and_reports_the_counts(tmp_path, capsys):
    root, _ = _system32(tmp_path)
    out = tmp_path / "baseline"
    out.mkdir()
    code = binary_graph.main(["--out", str(out), "--system32", str(root), "--build", "26220.5770", "--arch", "arm64"])
    assert code == 0
    lines = dict(line.split(": ", 1) for line in capsys.readouterr().out.splitlines())
    assert {k: lines[k] for k in ("binaries", "skipped", "api_sets", "resolved")} == {
        "binaries": "6", "skipped": "1", "api_sets": "1", "resolved": "2"}
    path = binary_graph.find_cache(str(out), "26220.5770", "arm64")
    assert path and lines["cache"] == path
    graph = binary_graph.load_graph(path, "26220.5770", "arm64")
    assert graph.resolved[("kernel32.dll", "HeapAlloc")].reason == "defined"      # the api-set map came from the tree


def test_the_cli_creates_the_output_directory(tmp_path, capsys):
    root, _ = _system32(tmp_path)
    out = tmp_path / "not" / "yet"
    assert binary_graph.main(["--out", str(out), "--system32", str(root), "--build", "1.1", "--arch", "x64"]) == 0
    assert binary_graph.find_cache(str(out), "1.1", "x64")


def test_the_cli_returns_one_when_the_directory_holds_no_pe(tmp_path, capsys):
    empty = tmp_path / "System32"
    empty.mkdir()
    (empty / "readme.dll").write_bytes(b"not a pe")
    out = tmp_path / "out"
    out.mkdir()
    assert binary_graph.main(["--out", str(out), "--system32", str(empty), "--build", "1.1", "--arch", "x64"]) == 1
    assert os.listdir(out) == []                                    # no graph of nothing is left behind
    assert binary_graph.main(["--out", str(out), "--system32", str(tmp_path / "gone"), "--build", "1.1", "--arch", "x64"]) == 1
    assert os.listdir(out) == []


def test_a_failed_cli_run_leaves_the_cache_of_an_earlier_run_alone(tmp_path, capsys):
    root, _ = _system32(tmp_path)
    out = tmp_path / "out"
    args = ["--out", str(out), "--build", "1.1", "--arch", "x64"]
    assert binary_graph.main(args + ["--system32", str(root)]) == 0
    before = (out / binary_graph.cache_name("1.1", "x64")).read_bytes()
    assert binary_graph.main(args + ["--system32", str(tmp_path / "gone")]) == 1
    assert (out / binary_graph.cache_name("1.1", "x64")).read_bytes() == before


def test_the_cli_returns_one_for_a_build_or_architecture_it_cannot_name_a_file_by(tmp_path, capsys):
    root, _ = _system32(tmp_path)
    for build, arch in (("../x", "x64"), ("1.1", "a/b")):
        assert binary_graph.main(["--out", str(tmp_path / "o"), "--system32", str(root), "--build", build, "--arch", arch]) == 1
    assert not (tmp_path / "o").exists() or os.listdir(tmp_path / "o") == []


def test_the_cli_returns_one_when_the_output_cannot_be_written(tmp_path, capsys):
    root, _ = _system32(tmp_path)
    blocker = tmp_path / "file"
    blocker.write_text("a file, not a directory")
    assert binary_graph.main(["--out", str(blocker), "--system32", str(root), "--build", "1.1", "--arch", "x64"]) == 1


def test_the_cli_returns_one_on_arguments_it_does_not_know_instead_of_exiting_the_interpreter(tmp_path, capsys):
    assert binary_graph.main([]) == 1
    assert binary_graph.main(["--out"]) == 1
    assert binary_graph.main(["--nonsense", "x"]) == 1


def test_the_build_and_architecture_default_to_the_ones_of_the_host(tmp_path, monkeypatch, capsys):
    root, _ = _system32(tmp_path)
    monkeypatch.setattr(binary_graph, "host_build", lambda: "26100.1")
    monkeypatch.setattr(binary_graph, "host_arch", lambda: "x64")
    assert binary_graph.main(["--out", str(tmp_path / "o"), "--system32", str(root)]) == 0
    assert binary_graph.find_cache(str(tmp_path / "o"), "26100.1", "x64")


def test_without_a_build_to_name_the_cache_by_the_cli_returns_one(tmp_path, monkeypatch, capsys):
    root, _ = _system32(tmp_path)
    monkeypatch.setattr(binary_graph, "host_build", lambda: None)
    assert binary_graph.main(["--out", str(tmp_path / "o"), "--system32", str(root), "--arch", "x64"]) == 1


def test_the_host_build_is_the_number_and_revision_of_the_registry(monkeypatch):
    import sys
    import types
    values = {"CurrentBuildNumber": ("26220", 1), "UBR": (5770, 4)}
    fake = types.SimpleNamespace(HKEY_LOCAL_MACHINE=0, OpenKey=lambda *a: _Key(), QueryValueEx=lambda key, name: values[name])
    monkeypatch.setitem(sys.modules, "winreg", fake)
    assert binary_graph.host_build() == "26220.5770"
    monkeypatch.setitem(sys.modules, "winreg", None)                 # not Windows
    assert binary_graph.host_build() is None


def test_the_host_build_asks_the_one_registry_seam_for_the_number_and_the_revision():
    asked = []
    held = {"CurrentBuildNumber": "26220", "UBR": 5770}

    def registry(subkey, name):
        asked.append((subkey, name))
        return held.get(name)

    assert binary_graph.host_build(registry) == "26220.5770"
    assert asked == [(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber"),
                     (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR")]


@pytest.mark.parametrize("missing", ["CurrentBuildNumber", "UBR"])
def test_a_build_the_registry_cannot_give_whole_is_none(missing):
    held = {"CurrentBuildNumber": "26220", "UBR": 5770}
    held.pop(missing)
    assert binary_graph.host_build(lambda subkey, name: held.get(name)) is None
    assert binary_graph.host_build(lambda subkey, name: None) is None


def test_a_registry_that_raises_gives_no_build():
    def broken(subkey, name):
        raise OSError("access denied")

    assert binary_graph.host_build(broken) is None


class _Key:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _registry(value):
    """A stand-in for the registry read: `value` is what PROCESSOR_ARCHITECTURE holds, None when it cannot be read."""
    return lambda subkey, name: value


def _machine(monkeypatch, machine):
    monkeypatch.setattr("platform.machine", lambda: machine)


@pytest.mark.parametrize("held,arch", [("ARM64", "arm64"), ("AMD64", "x64"), ("arm64", "arm64"), ("amd64", "x64")])
def test_the_host_architecture_is_the_registrys_whatever_the_interpreter_reports(monkeypatch, held, arch):
    # an x64 interpreter emulated on an ARM64 system says AMD64 (and the reverse is no better a witness): one cache, so
    # a wrong answer is no graph at all
    for machine in ("AMD64", "ARM64", "x86_64", "aarch64"):
        _machine(monkeypatch, machine)
        assert binary_graph.host_arch(_registry(held)) == arch, machine


def test_the_registry_is_asked_for_the_system_architecture_not_the_one_of_the_process(monkeypatch):
    asked = []

    def registry(subkey, name):
        asked.append((subkey, name))
        return "ARM64"

    _machine(monkeypatch, "AMD64")
    assert binary_graph.host_arch(registry) == "arm64"
    assert asked == [(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "PROCESSOR_ARCHITECTURE")]


@pytest.mark.parametrize("machine,arch", [("ARM64", "arm64"), ("aarch64", "arm64"), ("AMD64", "x64"), ("x86_64", "x64")])
def test_without_a_registry_answer_the_architecture_is_the_interpreters(monkeypatch, machine, arch):
    _machine(monkeypatch, machine)
    for answer in (None, "", "x86", "IA64", "garbage", 5):
        assert binary_graph.host_arch(_registry(answer)) == arch, answer


def test_a_registry_that_raises_is_the_same_as_one_that_cannot_be_read(monkeypatch):
    def broken(subkey, name):
        raise OSError("access denied")

    _machine(monkeypatch, "ARM64")
    assert binary_graph.host_arch(broken) == "arm64"
    _machine(monkeypatch, "AMD64")
    assert binary_graph.host_arch(broken) == "x64"


def test_the_default_registry_read_goes_through_winreg_and_gives_none_where_there_is_none(monkeypatch):
    import sys
    import types
    seen = []

    def query(key, name):
        seen.append(name)
        return ("ARM64", 1)

    fake = types.SimpleNamespace(HKEY_LOCAL_MACHINE=0, OpenKey=lambda root, subkey: _Key(), QueryValueEx=query)
    monkeypatch.setitem(sys.modules, "winreg", fake)
    _machine(monkeypatch, "AMD64")
    assert binary_graph.host_arch() == "arm64" and seen == ["PROCESSOR_ARCHITECTURE"]
    monkeypatch.setitem(sys.modules, "winreg", None)                 # not Windows
    assert binary_graph.host_arch() == "x64"
    _machine(monkeypatch, "ARM64")
    assert binary_graph.host_arch() == "arm64"

    def unreadable(root, subkey):
        raise OSError("no such key")

    monkeypatch.setitem(sys.modules, "winreg", types.SimpleNamespace(HKEY_LOCAL_MACHINE=0, OpenKey=unreadable))
    assert binary_graph.host_arch() == "arm64"


def test_the_module_runs_as_a_script_from_its_own_directory_with_nothing_else_of_the_web_ui(tmp_path):
    import subprocess
    import sys
    root, _ = _system32(tmp_path)
    lone = tmp_path / "lone"
    lone.mkdir()
    (lone / "binary_graph.py").write_bytes(open(binary_graph.__file__, "rb").read())      # as it sits on the VM, alone
    out = tmp_path / "out"
    proc = subprocess.run([sys.executable, "binary_graph.py", "--out", str(out), "--system32", str(root),
                           "--build", "1.1", "--arch", "x64"], cwd=str(lone), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "binaries: 6" in proc.stdout.splitlines()
    assert os.path.isfile(out / "binary-graph-1.1-x64.json")


# --- scripts/build-binary-graph.ps1 -------------------------------------------------------------

def _build_script():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "scripts", "build-binary-graph.ps1"), encoding="utf-8") as fh:
        return fh.read()


def test_the_build_script_parses():
    import shutil
    import subprocess
    pwsh = shutil.which("pwsh") or ("/opt/homebrew/bin/pwsh" if os.path.exists("/opt/homebrew/bin/pwsh") else None)
    if not pwsh:
        pytest.skip("pwsh not installed")
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "build-binary-graph.ps1")
    cmd = ("$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
           f"'{path}', [ref]$null, [ref]$e); if ($e) {{ $e | ForEach-Object {{ $_.Message }}; exit 1 }}")
    proc = subprocess.run([pwsh, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_build_script_never_ends_provisioning_with_an_error():
    script = _build_script()
    assert not re.search(r"(?m)(?:^|[;{])\s*exit\s+(?!0\b)\S", script), "a missing graph is a state the tab reports"
    assert not re.search(r"(?m)^[^#\n]*\bthrow\b", script)
    assert re.search(r"(?m)^\s*\[switch\]\$Force", script)
    assert "--out" in script and "$BaselineDir" in script and r"C:\tools\ntsleuth\baseline" in script
    assert r'$WebUiDir     = "C:\DetonationChamberUI"' in script and r'"$WebUiDir\venv\Scripts\python.exe"' in script
    # PowerShell 5.1 has none of these
    assert "??" not in script and not re.search(r"\$\w+\s*\?\s*[^\s]+\s*:", script) and "?." not in script


def test_the_build_script_is_provisioned_in_all_three_places_after_ntsleuth_and_the_web_ui():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name, ntsleuth, webui, mine in (
            ("Vagrantfile", "scripts/install-ntsleuth.ps1", "scripts/install-webui.ps1", "scripts/build-binary-graph.ps1"),
            ("Vagrantfile.utm", "scripts/install-ntsleuth.ps1", "scripts/install-webui.ps1", "scripts/build-binary-graph.ps1"),
            ("scripts/setup-macos-utm.sh", '"install-ntsleuth.ps1"', '"install-webui.ps1"', '"build-binary-graph.ps1"')):
        with open(os.path.join(root, *name.split("/")), encoding="utf-8") as fh:
            text = fh.read()
        assert text.count(mine) == 1, name
        assert text.index(ntsleuth) < text.index(mine) and text.index(webui) < text.index(mine), name
        assert text.index(mine) < text.index("configure-logging.ps1"), name


def _pwsh():
    import shutil
    pwsh = shutil.which("pwsh") or ("/opt/homebrew/bin/pwsh" if os.path.exists("/opt/homebrew/bin/pwsh") else None)
    if not pwsh:
        pytest.skip("pwsh not installed")
    return pwsh


def _run_build_script(tmp_path, module_source, *, python=True, force=False, existing=None):
    """Runs the script's own text with the registry reads replaced by an arm64 system of build 1.1, the paths moved into
    `tmp_path` and a stand-in for binary_graph.py: what it does with an interpreter, a module and a cache."""
    import subprocess
    import sys
    script = _build_script()
    head = script[:script.index("# OS architecture from the registry")]
    tail = script[script.index('$cacheName = "binary-graph'):]
    web, baseline = tmp_path / "webui", tmp_path / "baseline"
    web.mkdir(parents=True)
    baseline.mkdir()
    if module_source is not None:
        (web / "binary_graph.py").write_text(module_source)
    if existing is not None:
        (baseline / "binary-graph-1.1-arm64.json").write_text(existing)
    program = (head.replace("[switch]$Force", "[switch]$Force = $" + ("true" if force else "false"))
               + f"$BaselineDir = '{baseline}'; $WebUiDir = '{web}'; $Python = '{sys.executable if python else web / 'none'}'; "
                 f"$Module = '{web}/binary_graph.py'\n$arch = 'arm64'; $build = '1.1'\n"
               + tail.replace("$BaselineDir\\", "$BaselineDir/").replace("$env:TEMP\\", f"{tmp_path}/"))
    path = tmp_path / "run.ps1"
    path.write_text(program)
    proc = subprocess.run([_pwsh(), "-NoProfile", "-File", str(path)], capture_output=True, text=True, timeout=120)
    return proc, baseline


_FAKE_OK = ("import sys, os\n"
            "out = sys.argv[sys.argv.index('--out') + 1]\n"
            "open(os.path.join(out, 'binary-graph-' + sys.argv[sys.argv.index('--build') + 1] + '-' + sys.argv[sys.argv.index('--arch') + 1] + '.json'), 'w').write('{}')\n"
            "print('binaries: 12'); print('skipped: 2'); print('api_sets: 0'); print('resolved: 5'); print('modules: 7')\n")


def test_the_build_script_reports_the_numbers_of_a_build_that_worked(tmp_path):
    proc, baseline = _run_build_script(tmp_path, _FAKE_OK)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "binaries: 12" in proc.stdout and "resolved: 5" in proc.stdout and "[+] Binary graph" in proc.stdout
    assert "api-set map could not be read" in proc.stdout            # api_sets: 0 is a degraded graph, said so
    assert (baseline / "binary-graph-1.1-arm64.json").is_file()


@pytest.mark.parametrize("what,module,python", [
    ("the module exits 1", "import sys; print('binaries: 0'); sys.exit(1)", True),
    ("the module raises", "raise RuntimeError('boom')", True),
    ("the module exits 0 and writes nothing", "print('binaries: 3')", True),
    ("the module is not there", None, True),
    ("the interpreter is not there", "print('x')", False)])
def test_a_build_that_fails_is_a_warning_and_the_script_still_exits_zero(tmp_path, what, module, python):
    proc, baseline = _run_build_script(tmp_path, module, python=python)
    assert proc.returncode == 0, what + "\n" + proc.stdout + proc.stderr
    assert "[!]" in proc.stdout and "No graph was built" in proc.stdout, what
    assert not list(baseline.glob("binary-graph-*")), what


def _delegating_module(rebuilt_created="rebuilt"):
    """A stand-in module for the script: `--check` is the real module's, a build writes a whole cache (made recognisable by
    its `created`)."""
    return ("import sys, os\n"
            f"sys.path.insert(0, {os.path.dirname(binary_graph.__file__)!r})\n"
            "import binary_graph, dataclasses\n"
            "if '--check' in sys.argv:\n"
            "    sys.exit(binary_graph.main())\n"
            "arg = lambda name: sys.argv[sys.argv.index(name) + 1]\n"
            "import test_binary_graph\n"
            "graph = dataclasses.replace(test_binary_graph._strange_graph(), build=arg('--build'), arch=arg('--arch'),"
            f" created={rebuilt_created!r})\n"
            "binary_graph.save_graph(graph, os.path.join(arg('--out'), binary_graph.cache_name(arg('--build'), arg('--arch'))))\n"
            "print('binaries: 2')\n")


def _whole_cache(build="1.1", arch="arm64", created="original"):
    import dataclasses
    return dataclasses.replace(_strange_graph(), build=build, arch=arch, created=created)


def _created(baseline):
    return json.loads((baseline / "binary-graph-1.1-arm64.json").read_text())["created"]


def _run_with_cache(tmp_path, cache_bytes, force=False):
    """The script, a delegating module and a cache with these bytes in place; a subprocess needs the tests directory on its
    path to find _strange_graph."""
    import sys
    module = _delegating_module().replace("import test_binary_graph\n", f"sys.path.insert(0, {os.path.dirname(__file__)!r})\nimport test_binary_graph\n")
    proc, baseline = _run_build_script(tmp_path, module, force=force, existing=cache_bytes)
    return proc, baseline


def test_a_cache_that_is_there_and_loads_is_not_built_again_unless_forced(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    binary_graph.save_graph(_whole_cache(), str(src / "c.json"))
    whole = (src / "c.json").read_text()
    proc, baseline = _run_with_cache(tmp_path / "keep", whole)
    assert proc.returncode == 0 and "already present" in proc.stdout, proc.stdout + proc.stderr
    assert _created(baseline) == "original"
    proc, baseline = _run_with_cache(tmp_path / "forced", whole, force=True)
    assert proc.returncode == 0 and "[+] Binary graph" in proc.stdout, proc.stdout + proc.stderr
    assert _created(baseline) == "rebuilt"


@pytest.mark.parametrize("damage", ["cut", "zero-filled", "stamp of another build", "not json"])
def test_a_cache_that_is_there_but_does_not_load_is_built_again_not_kept_for_its_length(tmp_path, damage):
    src = tmp_path / "src"
    src.mkdir()
    binary_graph.save_graph(_whole_cache(), str(src / "c.json"))
    whole = (src / "c.json").read_text()
    other = _whole_cache(build="9.9")
    binary_graph.save_graph(other, str(src / "o.json"))
    damaged = {"cut": whole[:len(whole) // 2], "zero-filled": "\0" * len(whole), "not json": "x" * len(whole),
               "stamp of another build": (src / "o.json").read_text()}[damage]
    assert len(damaged) > 0
    proc, baseline = _run_with_cache(tmp_path / "run", damaged)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "does not load" in proc.stdout and "building it again" in proc.stdout, proc.stdout
    assert _created(baseline) == "rebuilt"
    binary_graph.load_graph(str(baseline / "binary-graph-1.1-arm64.json"), "1.1", "arm64")


def test_a_cache_that_is_there_and_a_module_that_cannot_rebuild_it_is_a_warning_and_exit_zero(tmp_path):
    proc, baseline = _run_build_script(tmp_path, "raise SystemExit(1)", existing="half")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "does not load" in proc.stdout and "No graph was built" in proc.stdout


def test_setup_gives_the_graph_script_more_time_than_the_build_waits_for():
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "scripts", "setup-macos-utm.sh"), encoding="utf-8") as fh:
        text = fh.read()
    function = re.search(r"(?ms)^provision_timeout\(\) \{.*?^\}", text).group(0)
    def timeout(name):
        return int(subprocess.run(["bash", "-c", function + f'\nprovision_timeout "{name}"'], capture_output=True,
                                  text=True, check=True).stdout)
    build_wait = int(re.search(r"\$BuildTimeout = (\d+)", _build_script()).group(1))
    assert timeout("build-binary-graph.ps1") > build_wait
    assert timeout("install-webui.ps1") == 900                 # nothing else changed
    assert 'run_provision_script "$script" "$(provision_timeout "$script")"' in text


def test_the_build_script_off_windows_finds_no_registry_and_still_exits_zero(tmp_path):
    import subprocess
    proc = subprocess.run([_pwsh(), "-NoProfile", "-File", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                                                       "scripts", "build-binary-graph.ps1")],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "No graph was built" in proc.stdout


# --- the queries over the graph (binary_graph_query) ---------------------------------------------

def _q(name, kind="dll", imports=None, exports=(), forwarders=None, partial=False):
    return binary_graph.BinaryInfo(name=name, kind=kind, machine="arm64", imports=dict(imports or {}),
                                   exports=tuple(exports), forwarders=dict(forwarders or {}), ordinal_names={},
                                   partial=partial)


def _query_graph(*infos, api_sets=None, build="26220.5770", arch="arm64"):
    """A Graph as build_graph makes one: resolved and in_degree are derived from the records, never written by hand."""
    binaries = {info.name: info for info in infos}
    api_sets = dict(api_sets or {})
    in_degree = {}
    for info in binaries.values():
        for module in info.imports:
            in_degree[module] = in_degree.get(module, 0) + 1
    return binary_graph.Graph(build=build, arch=arch, created="2026-11-23T10:00:00Z", binaries=binaries,
                              api_sets=api_sets, resolved=binary_graph.resolve_all(binaries, api_sets),
                              in_degree=in_degree, skipped=())


def _system():
    """A small System32: direct, forwarded and api-set paths to NtClose, and binaries that take none of them."""
    return _query_graph(
        _q("ntdll.dll", exports=["NtClose", "ZwClose", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory",
                                 "RtlAllocateHeap"]),
        _q("kernelbase.dll", imports={"ntdll.dll": ("NtClose", "NtAllocateVirtualMemory")},
           exports=["VirtualAlloc", "CloseHandle"],
           forwarders={"NtClose": "NTDLL.NtClose", "HeapAlloc": "NTDLL.RtlAllocateHeap"}),
        _q("kernel32.dll", imports={"api-ms-win-core-memory-l1-1-0.dll": ("VirtualAlloc",)},
           exports=["CloseHandle"],
           forwarders={"HeapAlloc": "api-ms-win-core-heap-l1-1-0.HeapAlloc", "CloseHandleNt": "NTDLL.ZwClose",
                       "Gone": "MISSING.Gone"}),
        _q("a.exe", "exe", imports={"ntdll.dll": ("NtClose",)}),
        _q("b.exe", "exe", imports={"kernel32.dll": ("CloseHandleNt", "VirtualAllocEx")}),
        _q("c.exe", "exe", imports={"api-ms-win-core-handle-l1-1-0.dll": ("NtClose",)}),
        _q("d.exe", "exe", imports={"kernel32.dll": ("CloseHandle",), "user32.dll": ("MessageBoxW",),
                                    "advapi32.dll": ("RegSetValueExW",)}),
        _q("e.exe", "exe", imports={"api-ms-win-core-memory-l1-1-0.dll": ("VirtualAlloc",),
                                    "user32.dll": ("MessageBoxW",)}),
        api_sets={"api-ms-win-core-heap-l1-1-0": ("kernelbase.dll",),
                  "api-ms-win-core-handle-l1-1-0": ("kernelbase.dll",),
                  "api-ms-win-core-memory-l1-1-0": ("kernelbase.dll",)})


def _ids(answer):
    return {node.id for node in answer.nodes}


def _node(answer, node_id):
    return next(node for node in answer.nodes if node.id == node_id)


def _edges(answer):
    return {(edge.source, edge.target, edge.kind) for edge in answer.edges}


def _whole(answer):
    """Every edge joins two nodes of the answer, and every root is one of them."""
    ids = _ids(answer)
    assert all(edge.source in ids and edge.target in ids for edge in answer.edges)
    assert set(answer.roots) <= ids


def test_who_imports_this_names_every_binary_with_an_import_edge_to_it():
    graph = _system()
    got = binary_graph_query.importers_of(graph, "kernel32.dll")
    assert _ids(got) == {"kernel32.dll", "b.exe", "d.exe"}
    assert _edges(got) == {("b.exe", "kernel32.dll", "imports"), ("d.exe", "kernel32.dll", "imports")}
    assert got.roots == ("kernel32.dll",)
    assert (_node(got, "b.exe").kind, _node(got, "kernel32.dll").kind) == ("exe", "dll")
    assert _node(got, "kernel32.dll").in_degree == graph.in_degree["kernel32.dll"] == 2
    assert all(edge.origin == "derived" for edge in got.edges)
    assert got.truncated is False and got.note
    # the name as a user types it
    assert binary_graph_query.importers_of(graph, "KERNEL32") == got
    _whole(got)


def test_who_imports_this_function_narrows_to_the_binaries_that_import_that_name():
    graph = _system()
    got = binary_graph_query.importers_of(graph, "kernel32.dll", "CloseHandle")
    assert _ids(got) == {"kernel32.dll", "d.exe"}           # b.exe imports kernel32.dll, but not CloseHandle
    assert [edge.label for edge in got.edges] == ["CloseHandle"]
    # most of System32 imports through an api set: the alias is drawn, and the host it resolves to
    via = binary_graph_query.importers_of(graph, "kernelbase.dll", "VirtualAlloc")
    assert _ids(via) == {"kernelbase.dll", "api-ms-win-core-memory-l1-1-0.dll", "kernel32.dll", "e.exe"}
    assert _edges(via) == {("kernel32.dll", "api-ms-win-core-memory-l1-1-0.dll", "imports"),
                           ("e.exe", "api-ms-win-core-memory-l1-1-0.dll", "imports"),
                           ("api-ms-win-core-memory-l1-1-0.dll", "kernelbase.dll", "resolves_to")}
    assert _node(via, "api-ms-win-core-memory-l1-1-0.dll").kind == "api-set"
    # an api set whose host does not offer the function is no importer of it, nor one that resolves elsewhere
    assert binary_graph_query.importers_of(graph, "kernelbase.dll", "Nowhere").nodes == ()
    assert binary_graph_query.importers_of(graph, "kernel32.dll", "VirtualAlloc").nodes == ()
    _whole(via)


def test_the_imports_of_a_binary_carry_the_suspicious_category_on_their_node(app_module):
    graph = _system()
    got = binary_graph_query.imports_of(graph, "b.exe")
    assert got.roots == ("b.exe",)
    assert _ids(got) == {"b.exe", "kernel32.dll!VirtualAllocEx", "kernel32.dll!CloseHandleNt"}
    assert _edges(got) == {("b.exe", "kernel32.dll!VirtualAllocEx", "imports"),
                           ("b.exe", "kernel32.dll!CloseHandleNt", "imports")}
    alloc = _node(got, "kernel32.dll!VirtualAllocEx")
    assert (alloc.kind, alloc.label) == ("function", "VirtualAllocEx")
    assert "VirtualAllocEx" in app_module.SUSPICIOUS_IMPORTS[alloc.category]
    assert _node(got, "kernel32.dll!CloseHandleNt").category == ""
    # SUSPICIOUS_IMPORTS names the function without its A or W: System32 imports it with one
    registry = _node(binary_graph_query.imports_of(graph, "d.exe"), "advapi32.dll!RegSetValueExW")
    assert "RegSetValueEx" in app_module.SUSPICIOUS_IMPORTS[registry.category]
    _whole(got)


def test_the_normal_callers_of_a_syscall_are_the_modules_whose_chain_reaches_ntdll():
    graph = _system()
    got = binary_graph_query.callers_of_syscall(graph, "NtClose")
    assert got.roots == ("syscall:NtClose",)
    assert _node(got, "syscall:NtClose").kind == "syscall"
    callers = {node.id for node in got.nodes if node.kind in ("dll", "exe")}
    # direct, through a forwarder to the Zw name, through an api set and a forwarder; d.exe's CloseHandle is code,
    # not a chain, and is no normal caller
    assert callers == {"a.exe", "b.exe", "c.exe", "kernelbase.dll"}
    assert {("c.exe", "api-ms-win-core-handle-l1-1-0.dll!NtClose", "imports"),
            ("api-ms-win-core-handle-l1-1-0.dll!NtClose", "kernelbase.dll!NtClose", "resolves_to"),
            ("kernelbase.dll!NtClose", "ntdll.dll!NtClose", "forwards_to"),
            ("ntdll.dll!NtClose", "syscall:NtClose", "reaches_syscall"),
            ("b.exe", "kernel32.dll!CloseHandleNt", "imports"),
            ("kernel32.dll!CloseHandleNt", "ntdll.dll!ZwClose", "forwards_to"),
            ("ntdll.dll!ZwClose", "syscall:NtClose", "reaches_syscall"),
            ("a.exe", "ntdll.dll!NtClose", "imports")} <= _edges(got)
    assert all(edge.origin == "derived" for edge in got.edges)
    # the Zw name is the same syscall
    assert binary_graph_query.callers_of_syscall(graph, "ZwClose") == got
    _whole(got)


def _follow(answer, start):
    """The node ids from `start` along the one edge out of each."""
    out = {}
    for edge in answer.edges:
        assert edge.source not in out, "a forwarder chain branches"
        out[edge.source] = edge.target
    path = [start]
    while path[-1] in out:
        path.append(out[path[-1]])
    return path


def test_the_forwarder_chains_of_a_module_draw_one_path_per_forwarded_export():
    graph = _system()
    got = binary_graph_query.forwarder_chains(graph, "kernel32.dll")
    assert set(got.roots) == {"kernel32.dll!HeapAlloc", "kernel32.dll!CloseHandleNt", "kernel32.dll!Gone"}
    assert _follow(got, "kernel32.dll!HeapAlloc") == [
        "kernel32.dll!HeapAlloc", "api-ms-win-core-heap-l1-1-0.dll!HeapAlloc", "kernelbase.dll!HeapAlloc",
        "ntdll.dll!RtlAllocateHeap"]
    assert _follow(got, "kernel32.dll!CloseHandleNt") == ["kernel32.dll!CloseHandleNt", "ntdll.dll!ZwClose"]
    # a chain into a module that is not there is drawn as far as it goes, and the note says so
    assert _follow(got, "kernel32.dll!Gone") == ["kernel32.dll!Gone", "missing.dll!Gone"]
    assert "missing" in got.note or "not in the graph" in got.note
    assert {edge.kind for edge in got.edges} == {"forwards_to", "resolves_to"}
    _whole(got)


def test_the_shared_dependencies_of_two_binaries_are_the_modules_both_import():
    graph = _system()
    got = binary_graph_query.shared_dependencies(graph, "d.exe", "e.exe")
    assert got.roots == ("d.exe", "e.exe")
    assert _ids(got) == {"d.exe", "e.exe", "user32.dll"}
    assert _edges(got) == {("d.exe", "user32.dll", "imports"), ("e.exe", "user32.dll", "imports")}
    assert _node(got, "user32.dll").in_degree == 2
    assert got.total == 1
    _whole(got)


def test_two_binaries_that_reach_one_module_through_different_api_sets_share_it():
    # kernel32.dll imports the memory api set, c.exe the handle one: both are kernelbase.dll to the loader
    graph = _system()
    got = binary_graph_query.shared_dependencies(graph, "kernel32.dll", "c.exe")
    assert _ids(got) == {"kernel32.dll", "c.exe", "kernelbase.dll", "api-ms-win-core-memory-l1-1-0.dll",
                         "api-ms-win-core-handle-l1-1-0.dll"}
    assert _edges(got) == {("kernel32.dll", "api-ms-win-core-memory-l1-1-0.dll", "imports"),
                           ("api-ms-win-core-memory-l1-1-0.dll", "kernelbase.dll", "resolves_to"),
                           ("c.exe", "api-ms-win-core-handle-l1-1-0.dll", "imports"),
                           ("api-ms-win-core-handle-l1-1-0.dll", "kernelbase.dll", "resolves_to")}
    assert "api-set resolution" in got.note
    # one binary through an api set, the other directly: the same module too
    direct = _query_graph(_q("kernelbase.dll"), _q("x.exe", "exe", imports={"kernelbase.dll": ("F",)}),
                          _q("y.exe", "exe", imports={"api-ms-win-core-memory-l1-1-0.dll": ("F",)}),
                          api_sets={"api-ms-win-core-memory-l1-1-0": ("kernelbase.dll",)})
    both = binary_graph_query.shared_dependencies(direct, "x.exe", "y.exe")
    assert ("x.exe", "kernelbase.dll", "imports") in _edges(both) and both.total == 1
    _whole(got)


def _is_sentence(note):
    # a module name opens many notes and is lower case: prose is words and a full stop
    return len(note.split()) > 3 and note.endswith(".")


def test_a_binary_that_is_not_in_the_graph_gives_an_empty_answer_with_a_note():
    graph = _system()
    for answer in (binary_graph_query.importers_of(graph, "nothere.dll"),
                   binary_graph_query.importers_of(graph, "kernel32.dll", "NoSuchFunction"),
                   binary_graph_query.imports_of(graph, "nothere.dll"),
                   binary_graph_query.callers_of_syscall(graph, "NtNothing"),
                   binary_graph_query.forwarder_chains(graph, "nothere.dll"),
                   binary_graph_query.forwarder_chains(graph, "a.exe"),            # there, and forwards nothing
                   binary_graph_query.shared_dependencies(graph, "d.exe", "nothere.dll")):
        assert (answer.nodes, answer.edges, answer.roots, answer.truncated) == ((), (), (), False)
        assert _is_sentence(answer.note), answer.note
    assert "nothere.dll" in binary_graph_query.imports_of(graph, "nothere.dll").note


def _hub(importers):
    return _query_graph(_q("hub.dll", exports=["F"]),
                        *(_q(f"user{n:04}.exe", "exe", imports={"hub.dll": ("F",)}) for n in range(importers)))


def test_an_answer_over_max_nodes_is_cut_and_says_truncated():
    assert binary_graph_query.MAX_NODES == 400
    got = binary_graph_query.importers_of(_hub(500), "hub.dll")
    assert len(got.nodes) == binary_graph_query.MAX_NODES
    assert got.truncated is True
    assert "400" in got.note and "500" in got.note
    # how many there were, for a view to show "399 of 500" without reading the prose
    assert got.total == 500
    _whole(got)
    small = binary_graph_query.importers_of(_hub(binary_graph_query.MAX_NODES - 1), "hub.dll")
    assert (len(small.nodes), small.truncated, small.total) == (binary_graph_query.MAX_NODES, False, 399)
    assert binary_graph_query.imports_of(_hub(1), "nothere.dll").total == 0


def test_a_truncated_answer_keeps_its_roots_so_the_view_still_has_a_starting_point():
    got = binary_graph_query.importers_of(_hub(500), "hub.dll")
    assert got.roots == ("hub.dll",) and "hub.dll" in _ids(got)
    # a cut drops whole paths, never half of one: every chain that is kept still reaches its end
    many = _query_graph(_q("ntdll.dll", exports=[f"F{n}" for n in range(300)]),
                        _q("k.dll", forwarders={f"F{n}": f"NTDLL.F{n}" for n in range(300)}))
    chains = binary_graph_query.forwarder_chains(many, "k.dll")
    assert chains.truncated is True and len(chains.nodes) <= binary_graph_query.MAX_NODES
    assert chains.roots
    for root in chains.roots:
        assert _follow(chains, root) == [root, "ntdll.dll!" + root.split("!", 1)[1]]
    assert len(chains.nodes) == 2 * len(chains.roots)
    _whole(chains)


def test_the_detail_of_a_node_names_its_imports_exports_forwarders_and_in_degree():
    graph = _system()
    got = binary_graph_query.node_detail(graph, "kernel32.dll")
    assert got["name"] == "kernel32.dll" and got["is"] == "binary"
    assert (got["kind"], got["machine"], got["in_degree"], got["partial"]) == ("dll", "arm64", 2, False)
    assert got["imports"] == {"api-ms-win-core-memory-l1-1-0.dll": ["VirtualAlloc"]}
    assert got["exports"] == ["CloseHandle"]
    assert got["forwarders"]["CloseHandleNt"] == {"raw": "NTDLL.ZwClose", "reason": "defined",
                                                  "module": "ntdll.dll", "function": "ZwClose", "partial": False}
    assert got["forwarders"]["Gone"]["reason"] == "missing"
    assert binary_graph_query.node_detail(graph, "KERNEL32")["name"] == "kernel32.dll"
    # imported, but not a file of the graph
    missing = binary_graph_query.node_detail(graph, "user32.dll")
    assert (missing["is"], missing["in_degree"]) == ("none", 2)
    json.dumps(got)


def test_the_detail_of_an_api_set_name_names_its_host_modules():
    graph = _system()
    got = binary_graph_query.node_detail(graph, "api-ms-win-core-memory-l1-1-0.dll")
    assert got["is"] == "api-set" and got["kind"] == "api-set"
    assert got["hosts"] == ["kernelbase.dll"]
    assert got["in_degree"] == 2
    assert binary_graph_query.node_detail(graph, "api-ms-win-core-memory-l1-1-0")["hosts"] == ["kernelbase.dll"]
    json.dumps(got)


# --- the two routes --------------------------------------------------------------------------------------------

_PARAMS = {"importers": "module=kernel32.dll&function=CloseHandle", "imports": "module=b.exe",
           "syscall-callers": "syscall=NtClose", "forwarders": "module=kernel32.dll", "shared": "module=d.exe&other=e.exe"}


@pytest.fixture
def graph_host(tdc, monkeypatch):
    """This system is build 26220.5770 on ARM64, and the web UI's Python an emulated x64 one: platform.machine()
    says AMD64, the registry (host_arch) says arm64. The cache of _system() lies where the web UI looks."""
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26220.5770")
    monkeypatch.setattr(tdc.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(tdc.binary_graph, "host_arch", lambda *a, **k: "arm64")
    builds = []
    real_build = tdc._build_binary_graph
    monkeypatch.setattr(tdc, "_build_binary_graph", lambda build, arch: builds.append((build, arch)))
    directory = tdc.NTSLEUTH_BASELINE_DIR
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, binary_graph.cache_name("26220.5770", "arm64"))
    binary_graph.save_graph(_system(), path)
    return path, builds, real_build


def _join(tdc):
    thread = tdc._binary_graph_build_state["thread"]
    if thread is not None:
        thread.join(5)


def test_the_query_route_answers_each_query_name_and_refuses_an_unknown_one(client, graph_host):
    assert set(_PARAMS) == set(binary_graph_query.QUERIES)
    for name, params in _PARAMS.items():
        r = client.get(f"/api/binary-graph/query?q={name}&{params}")
        assert r.status_code == 200, (name, r.get_json())
        body = r.get_json()
        assert body["nodes"] and body["roots"] and body["note"], name
        assert (body["build"], body["arch"], body["created"]) == ("26220.5770", "arm64", "2026-11-23T10:00:00Z")
        assert body["truncated"] is False
        assert body["total"] >= 1
        assert set(body["nodes"][0]) == {"id", "label", "kind", "in_degree", "category"}
        assert set(body["edges"][0]) == {"source", "target", "kind", "origin", "label"}
    callers = client.get("/api/binary-graph/query?q=syscall-callers&syscall=NtClose").get_json()
    assert callers["roots"] == ["syscall:NtClose"]
    r = client.get("/api/binary-graph/query?q=everything&module=kernel32.dll")
    assert r.status_code == 400 and "importers" in r.get_json()["error"]
    assert client.get("/api/binary-graph/query?module=kernel32.dll").status_code == 400
    # a query without the parameter it needs is refused, and says which
    r = client.get("/api/binary-graph/query?q=shared&module=d.exe")
    assert r.status_code == 400 and "other" in r.get_json()["error"]
    # a name that finds nothing is an answer, with its note: not a refusal
    r = client.get("/api/binary-graph/query?q=imports&module=nothere.dll")
    assert r.status_code == 200 and r.get_json()["nodes"] == [] and "nothere.dll" in r.get_json()["note"]


def test_the_query_route_says_so_when_no_cache_matches_this_build(client, tdc, graph_host, monkeypatch):
    path, builds, _ = graph_host
    os.replace(path, os.path.join(os.path.dirname(path), binary_graph.cache_name("26220.5770", "x64")))
    r = client.get("/api/binary-graph/query?q=imports&module=b.exe")
    assert r.status_code == 404
    body = r.get_json()
    assert body["cache"] is None and "nodes" not in body
    assert "26220.5770" in body["error"] and "arm64" in body["error"]
    _join(tdc)
    # one is built in the background, for the architecture of the system, not the one of the interpreter
    assert builds == [("26220.5770", "arm64")]
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    r = client.get("/api/binary-graph/query?q=imports&module=b.exe")
    assert r.status_code == 404 and r.get_json()["cache"] is None and "26300.1" in r.get_json()["error"]
    monkeypatch.setattr(tdc, "_current_os_build", lambda: None)
    r = client.get("/api/binary-graph/node?name=b.exe")
    assert r.status_code == 404 and r.get_json()["cache"] is None


def test_the_node_route_answers_a_binary_and_four_oh_fours_an_unknown_name(client, graph_host):
    r = client.get("/api/binary-graph/node?name=kernel32.dll")
    assert r.status_code == 200
    body = r.get_json()
    assert (body["is"], body["in_degree"], body["exports"]) == ("binary", 2, ["CloseHandle"])
    assert body["build"] == "26220.5770" and body["arch"] == "arm64"
    assert client.get("/api/binary-graph/node?name=api-ms-win-core-memory-l1-1-0").get_json()["hosts"] == ["kernelbase.dll"]
    r = client.get("/api/binary-graph/node?name=nowhere.dll")
    assert r.status_code == 404 and "nowhere.dll" in r.get_json()["error"]
    assert r.get_json()["cache"] is not None            # the graph is there; it is the name it does not know
    assert client.get("/api/binary-graph/node").status_code == 400


def test_the_graph_is_loaded_once_and_held_across_requests(client, tdc, graph_host, monkeypatch):
    loads = []
    real = binary_graph.load_graph
    monkeypatch.setattr(tdc.binary_graph, "load_graph", lambda *a: loads.append(a) or real(*a))
    for _ in range(3):
        assert client.get("/api/binary-graph/query?q=imports&module=b.exe").status_code == 200
    assert client.get("/api/binary-graph/node?name=b.exe").status_code == 200
    assert len(loads) == 1
    # a rebuilt cache is a new file: that one is read, once
    path, _, _ = graph_host
    binary_graph.save_graph(_query_graph(_q("b.exe", "exe", imports={"x.dll": ("F",)})), path)
    os.utime(path, ns=(1, 1))
    assert client.get("/api/binary-graph/query?q=imports&module=b.exe").get_json()["nodes"][1]["id"] == "x.dll!F"
    assert len(loads) == 2


def test_an_unusable_cache_is_refused_with_its_reason_and_not_read_again(client, tdc, graph_host, monkeypatch):
    path, builds, _ = graph_host
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"format": 1, "build": "26220.5770", "arch": "arm64"')
    loads = []
    real = binary_graph.load_graph
    monkeypatch.setattr(tdc.binary_graph, "load_graph", lambda *a: loads.append(a) or real(*a))
    for _ in range(2):
        r = client.get("/api/binary-graph/query?q=imports&module=b.exe")
        assert r.status_code == 404 and r.get_json()["cache"] is None and "malformed" in r.get_json()["error"]
    assert len(loads) == 1


def test_an_update_is_refused_while_the_binary_graph_is_being_built(tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_probe_http", lambda url, timeout=2: None)
    assert tdc._update_preconditions() is None
    started, release = threading.Event(), threading.Event()

    def slow(build, arch):
        started.set()
        release.wait(10)

    monkeypatch.setattr(tdc, "_build_binary_graph", slow)
    assert tdc._start_binary_graph_build("26220.5770", "arm64") is True
    try:
        assert started.wait(5)
        assert tdc._update_preconditions() == "A binary graph is being built. Wait until it finishes."
        assert tdc._start_binary_graph_build("26220.5770", "arm64") is False       # one at a time
    finally:
        release.set()
    _join(tdc)
    assert tdc._update_preconditions() is None


class _Updating:
    maintenance = True


def test_no_binary_graph_is_built_while_the_tools_are_being_updated(client, tdc, graph_host, monkeypatch):
    path, builds, _ = graph_host
    os.remove(path)
    monkeypatch.setattr(tdc, "_update_manager", _Updating())
    r = client.get("/api/binary-graph/query?q=imports&module=b.exe")
    assert r.status_code == 404 and "updat" in r.get_json()["error"]
    assert tdc._binary_graph_build_state["thread"] is None and builds == []


def test_a_build_that_fails_says_why_in_the_refusal_and_is_not_retried_at_once(client, tdc, graph_host, monkeypatch):
    path, _, real_build = graph_host
    os.remove(path)
    calls = []

    def run(args, timeout=None, **kwargs):
        calls.append(args)
        # what binary_graph.py says when the web UI holds the old cache open on Windows
        return subprocess.CompletedProcess(args, 1, "binaries: 4012\n", "the cache cannot be written (PermissionError)\n")

    monkeypatch.setattr(tdc, "_run_cmd", run)
    monkeypatch.setattr(tdc, "_build_binary_graph", real_build)
    client.get("/api/binary-graph/query?q=imports&module=b.exe")
    _join(tdc)
    assert len(calls) == 1
    args = calls[0]
    assert args[1].endswith("binary_graph.py")
    assert args[2:] == ["--out", tdc.NTSLEUTH_BASELINE_DIR, "--build", "26220.5770", "--arch", "arm64"]
    r = client.get("/api/binary-graph/query?q=imports&module=b.exe")
    body = r.get_json()
    assert r.status_code == 404 and "PermissionError" in body["error"]
    assert body["building"] is False
    # it says when, and when it is tried again
    assert body["failed"]["reason"] == "binary_graph.py exited with 1: the cache cannot be written (PermissionError)"
    assert body["failed"]["retry_at"] > body["failed"]["at"]
    assert "tried again" in body["error"]
    _join(tdc)
    assert len(calls) == 1                                   # held back for a while, not run on every request


_CUT = '{"format": 1, "build": "26220.5770", "arch": "arm64"'


def test_a_cache_that_does_not_load_is_rebuilt_in_the_background_like_a_missing_one(client, tdc, graph_host,
                                                                                     monkeypatch):
    path, builds, _ = graph_host
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_CUT)
    release = threading.Event()
    monkeypatch.setattr(tdc, "_build_binary_graph", lambda build, arch: builds.append((build, arch)) or release.wait(10))
    try:
        body = client.get("/api/binary-graph/query?q=imports&module=b.exe").get_json()
        assert builds == [("26220.5770", "arm64")]
        assert body["cache"] is None and body["building"] is True and body["failed"] is None
        assert "malformed" in body["error"] and "being built" in body["error"]
        assert "delete" not in body["error"]
    finally:
        release.set()
    _join(tdc)


def test_a_rebuild_that_leaves_a_cache_that_still_does_not_load_is_a_failure_not_a_loop(client, tdc, graph_host):
    path, builds, _ = graph_host
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_CUT)
    client.get("/api/binary-graph/query?q=imports&module=b.exe")
    _join(tdc)
    assert len(builds) == 1                     # the recorder "built" and left the cut file where it was
    for _ in range(3):
        body = client.get("/api/binary-graph/query?q=imports&module=b.exe").get_json()
        _join(tdc)
        assert body["failed"] and "does not load" in body["failed"]["reason"] and body["building"] is False
    assert len(builds) == 1


def test_a_failure_record_vanishes_once_a_usable_cache_exists_whoever_wrote_it(client, tdc, graph_host):
    path, builds, _ = graph_host
    os.remove(path)
    key = ("26220.5770", "arm64")
    tdc._binary_graph_build_state["failed"][key] = (tdc.time.time(), "binary_graph.py exited with 1: boom")
    body = client.get("/api/binary-graph/query?q=imports&module=b.exe").get_json()
    assert body["failed"]["reason"].endswith("boom") and builds == []          # held back by the record
    # the provisioning script writes the cache, without the web UI
    binary_graph.save_graph(_system(), path)
    r = client.get("/api/binary-graph/query?q=imports&module=b.exe")
    assert r.status_code == 200
    assert key not in tdc._binary_graph_build_state["failed"]
    # and the record holds nothing back any more: the cache gone again, a build starts at once
    os.remove(path)
    body = client.get("/api/binary-graph/query?q=imports&module=b.exe").get_json()
    _join(tdc)
    assert builds == [key] and body["failed"] is None


def _past_the_throttle(tdc, key):
    """Move the last failure of `key` back past the throttle, as ten minutes passing would."""
    at, why = tdc._binary_graph_build_state["failed"][key]
    tdc._binary_graph_build_state["failed"][key] = (at - tdc.BINARY_GRAPH_BUILD_RETRY - 1, why)


def test_a_cache_that_keeps_failing_is_rebuilt_three_times_and_then_left_to_a_rebuild_by_hand(client, tdc, graph_host):
    path, builds, _ = graph_host
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_CUT)
    key = ("26220.5770", "arm64")
    assert tdc.BINARY_GRAPH_BUILD_ATTEMPTS == 3
    for attempt in range(1, 4):
        client.get("/api/binary-graph/query?q=imports&module=b.exe")       # starts a build; the cut file stays
        _join(tdc)
        body = client.get("/api/binary-graph/query?q=imports&module=b.exe").get_json()     # which did not help
        _join(tdc)
        assert len(builds) == attempt and body["failed"]["attempts"] == attempt
        _past_the_throttle(tdc, key)
    # past the throttle, and still no fourth build: the refusal says how often and what to do
    for _ in range(2):
        body = client.get("/api/binary-graph/query?q=imports&module=b.exe").get_json()
        _join(tdc)
    assert len(builds) == 3
    assert body["building"] is False and body["failed"]["attempts"] == 3 and body["failed"]["retry_at"] is None
    assert "3 attempts" in body["error"] and "build-binary-graph.ps1 -Force" in body["error"]
    assert "tried again" not in body["error"]
    # a usable cache, written without the web UI, clears the record and its count: the tab is back without a restart
    binary_graph.save_graph(_system(), path)
    assert client.get("/api/binary-graph/query?q=imports&module=b.exe").status_code == 200
    assert key not in tdc._binary_graph_build_state["failed"]
    assert key not in tdc._binary_graph_build_state["attempts"]
    os.remove(path)
    client.get("/api/binary-graph/query?q=imports&module=b.exe")
    _join(tdc)
    assert len(builds) == 4


def test_failed_builds_of_a_missing_cache_count_toward_the_cap_too(client, tdc, graph_host, monkeypatch):
    path, _, _ = graph_host
    os.remove(path)
    key = ("26220.5770", "arm64")
    calls = []

    def failing(build, arch):
        calls.append(build)
        raise RuntimeError("binary_graph.py exited with 1: the cache cannot be written (OSError)")

    monkeypatch.setattr(tdc, "_build_binary_graph", failing)
    for _ in range(5):
        client.get("/api/binary-graph/query?q=imports&module=b.exe")
        _join(tdc)
        if key in tdc._binary_graph_build_state["failed"]:
            _past_the_throttle(tdc, key)
    assert len(calls) == 3
    body = client.get("/api/binary-graph/query?q=imports&module=b.exe").get_json()
    assert "3 attempts" in body["error"] and "OSError" in body["error"]


def test_a_query_without_a_parameter_it_needs_is_refused_before_any_graph_is_fetched(client, tdc, graph_host):
    path, builds, _ = graph_host
    os.remove(path)
    r = client.get("/api/binary-graph/query?q=shared&module=d.exe")
    _join(tdc)
    assert r.status_code == 400 and "other" in r.get_json()["error"]
    assert builds == [] and tdc._binary_graph_build_state["thread"] is None


def test_the_parameters_each_query_needs_are_the_ones_its_adapter_reads():
    ctx = binary_graph_query.Context(_system())
    given = {"module": "d.exe", "function": "", "syscall": "NtClose", "other": "e.exe", "metric": ""}
    for name, run in binary_graph_query.QUERIES.items():
        needs = binary_graph_query.NEEDS[name]
        binary_graph_query.check_parameters(name, {key: given[key] for key in needs})
        run(ctx, {key: given[key] for key in needs})
        for left_out in needs:
            params = {key: given[key] for key in needs if key != left_out}
            with pytest.raises(binary_graph_query.MissingParameter):
                binary_graph_query.check_parameters(name, params)
            with pytest.raises(binary_graph_query.MissingParameter):
                run(ctx, params)


def test_a_cache_that_cannot_be_opened_right_now_is_tried_again_not_rebuilt(client, tdc, graph_host, monkeypatch):
    # a scanner holding the freshly written file without read sharing: the file is fine, it only cannot be opened
    _, builds, _ = graph_host
    real = binary_graph.load_graph
    loads = []

    def flaky(*args):
        loads.append(args)
        if len(loads) == 1:
            raise binary_graph.CacheMismatch("unreadable", "the cache file cannot be opened")
        return real(*args)

    monkeypatch.setattr(tdc.binary_graph, "load_graph", flaky)
    r = client.get("/api/binary-graph/query?q=imports&module=b.exe")
    _join(tdc)
    assert r.status_code == 404 and r.get_json()["cache"] is None and "next request" in r.get_json()["error"]
    assert builds == [] and tdc._binary_graph_build_state["failed"] == {}
    assert client.get("/api/binary-graph/query?q=imports&module=b.exe").status_code == 200
    assert len(loads) == 2


def test_a_build_that_ends_well_but_leaves_no_cache_counts_as_a_failure(client, tdc, graph_host):
    path, builds, _ = graph_host
    os.remove(path)                                      # and the recorder that "builds" writes nothing
    client.get("/api/binary-graph/query?q=imports&module=b.exe")
    _join(tdc)
    key = ("26220.5770", "arm64")
    assert tdc._binary_graph_build_state["attempts"][key] == 1
    body = client.get("/api/binary-graph/query?q=imports&module=b.exe").get_json()
    _join(tdc)
    assert len(builds) == 1 and "left no cache" in body["failed"]["reason"]


def test_the_build_runs_below_normal_priority(tdc, monkeypatch):
    seen = {}

    def run(args, timeout=None, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(tdc, "_run_cmd", run)
    monkeypatch.setattr(tdc.subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0x4000, raising=False)
    tdc._build_binary_graph("26220.5770", "arm64")
    assert seen["creationflags"] & 0x4000


def test_a_deleted_cache_lets_go_of_the_graph_it_held(client, tdc, graph_host):
    path, _, _ = graph_host
    assert client.get("/api/binary-graph/query?q=imports&module=b.exe").status_code == 200
    assert tdc._binary_graph_held
    os.remove(path)
    assert client.get("/api/binary-graph/query?q=imports&module=b.exe").status_code == 404
    _join(tdc)
    assert tdc._binary_graph_held == {}


# --- the doors of a process: the union over every loaded module (binary_graph_query.imported_doors) -------------------

_SYS32 = "C:\\Windows\\System32\\"
_IMAGE = "C:\\Samples\\sample.exe"


def _doors_graph(*extra, arch="x64"):
    """A System32 in which no binary imports a door to NtWriteVirtualMemory, whatever ntdll and kernelbase export."""
    return _query_graph(
        _q("ntdll.dll", exports=["NtWriteVirtualMemory", "ZwWriteVirtualMemory", "NtClose", "ZwClose"]),
        _q("kernelbase.dll", imports={"ntdll.dll": ("NtClose",)}, exports=["WriteProcessMemory", "CloseHandle"]),
        _with_ordinals(_q("kernel32.dll", imports={"kernelbase.dll": ("CloseHandle",)}, exports=["CloseHandle"],
                          forwarders={"WriteProcessMemory": "kernelbase.WriteProcessMemory"}),
                       {157: "WriteProcessMemory", 158: "CloseHandle"}),
        *extra, arch=arch)


def _image(*functions):
    """The record of the process image, read from its file as binary_graph reads a System32 binary."""
    return _q("sample.exe", "exe", imports={"kernel32.dll": tuple(functions) or ("GetLastError",)})


def _loaded(*paths):
    """The reader's module list: the image first, as EnumProcessModulesEx gives it."""
    return [{"name": path.rsplit("\\", 1)[-1], "base": 0x7FF000000000 + i * 0x100000, "size": 0x1000, "path": path}
            for i, path in enumerate(paths)]


_SYSTEM_MODULES = tuple(_SYS32 + name for name in ("ntdll.dll", "kernel32.dll", "kernelbase.dll"))


def _doors(graph, modules, image=None, view="x64", image_path=_IMAGE):
    return binary_graph_query.imported_doors(graph, modules, win32_to_nt.load_table(), view=view,
                                             image_path=image_path, image=image if image is not None else _image())


def _process_hit(baseline, doors):
    """The one hit of a NtWriteVirtualMemory stub in private memory, searched as the web UI searches a process: with
    the union and its coverage when there is one, with nothing that could prove when there is none."""
    table = win32_to_nt.load_table()
    keywords = {"expanded_imports": doors, "covered": table.covered} if doors is not None else {}
    (hit,) = syscall_scan.find_stubs_in_process(_x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3"), baseline,
                                                None, **keywords)
    return hit


def test_a_loaded_module_the_cache_does_not_know_keeps_the_answer_unknown(x64_baseline):
    # a sample's own DLL, and a DLL in System32 the cache does not hold (dropped there after the build, or skipped):
    # its imports are a door the union cannot see, and a missing door is a false accusation
    for stranger in ("C:\\Samples\\helper.dll", _SYS32 + "dropped.dll"):
        doors = _doors(_doors_graph(), _loaded(_IMAGE, *_SYSTEM_MODULES, stranger))
        assert _process_hit(x64_baseline, doors)["import_present"] is None, stranger
        assert doors is None, stranger


def test_a_process_whose_modules_import_no_door_still_proves_a_bypass(x64_baseline):
    # ntdll exports NtWriteVirtualMemory and kernelbase WriteProcessMemory: a door is what a module imports, never
    # what one exports, or ntdll alone would switch the proof off in every process
    doors = _doors(_doors_graph(), _loaded(_IMAGE, *_SYSTEM_MODULES))
    assert "GetLastError" in doors and "CloseHandle" in doors and "NtClose" in doors
    hit = _process_hit(x64_baseline, doors)
    assert hit["import_present"] is False
    (finding,) = memory_evidence.from_direct_stubs([hit], "sample.exe")
    assert finding["needs_corroboration"] is False


def test_the_doors_of_every_loaded_module_count_as_the_documented_path(x64_baseline):
    # dbghelp, not the sample, imports WriteProcessMemory: the process holds a door, whoever's it is
    dbghelp = _q("dbghelp.dll", imports={"kernel32.dll": ("WriteProcessMemory",)})
    doors = _doors(_doors_graph(dbghelp), _loaded(_IMAGE, *_SYSTEM_MODULES, _SYS32 + "dbghelp.dll"))
    assert "NtWriteVirtualMemory" in doors
    assert _process_hit(x64_baseline, doors)["import_present"] is True
    # and the image's own imports count as well, read from its file
    doors = _doors(_doors_graph(), _loaded(_IMAGE, *_SYSTEM_MODULES), image=_image("WriteProcessMemory"))
    assert _process_hit(x64_baseline, doors)["import_present"] is True


def test_a_module_outside_system32_contributes_no_exports_to_the_union(x64_baseline):
    # a sample side-loads its own version.dll, or a kernel32.dll of its folder: the cache's record of the System32
    # file of that name says nothing about the file loaded, its imports no more than its exports
    version = _q("version.dll", imports={"kernel32.dll": ("CloseHandle",)}, exports=["GetFileVersionInfoW"])
    for planted in ("C:\\Samples\\version.dll", "C:\\Samples\\kernel32.dll", _SYS32 + "downlevel\\version.dll",
                    "C:\\Windows\\SysWOW64\\version.dll", "\\\\?\\C:\\Windows\\System32\\version.dll"):
        modules = _loaded(_IMAGE, *[m for m in _SYSTEM_MODULES if not planted.endswith("kernel32.dll")
                                    or "kernel32" not in m], planted)
        doors = _doors(_doors_graph(version), modules)
        assert _process_hit(x64_baseline, doors)["import_present"] is None, planted
    # the same name loaded from System32 is the file the cache read
    doors = _doors(_doors_graph(version), _loaded(_IMAGE, *_SYSTEM_MODULES, "c:\\windows\\system32\\VERSION.DLL"))
    assert _process_hit(x64_baseline, doors)["import_present"] is False


def test_a_record_cut_short_when_it_was_read_leaves_the_union_incomplete(x64_baseline):
    # the door may be in the part of the import table pefile did not read
    cut = _q("dbghelp.dll", imports={"kernel32.dll": ("CloseHandle",)}, partial=True)
    doors = _doors(_doors_graph(cut), _loaded(_IMAGE, *_SYSTEM_MODULES, _SYS32 + "dbghelp.dll"))
    assert _process_hit(x64_baseline, doors)["import_present"] is None
    cut_image = _q("sample.exe", "exe", imports={"kernel32.dll": ("GetLastError",)}, partial=True)
    doors = _doors(_doors_graph(), _loaded(_IMAGE, *_SYSTEM_MODULES), image=cut_image)
    assert _process_hit(x64_baseline, doors)["import_present"] is None


def _with_ordinals(info, ordinal_names):
    return binary_graph.BinaryInfo(**{**info.__dict__, "ordinal_names": dict(ordinal_names)})


def test_an_import_by_ordinal_counts_by_the_name_the_cache_gives_it(x64_baseline):
    kernelbase = _with_ordinals(_q("kernelbase.dll", imports={"ntdll.dll": ("NtClose",)},
                                   exports=["WriteProcessMemory", "CloseHandle"]), {7: "WriteProcessMemory"})
    graph = _doors_graph()
    graph = _query_graph(*[kernelbase if name == "kernelbase.dll" else info for name, info in graph.binaries.items()],
                         _q("dbghelp.dll", imports={"kernelbase.dll": ("#7",)}), arch="x64")
    doors = _doors(graph, _loaded(_IMAGE, *_SYSTEM_MODULES, _SYS32 + "dbghelp.dll"))
    assert _process_hit(x64_baseline, doors)["import_present"] is True
    # the image imports by ordinal as well: its record is read like any other
    image = _q("sample.exe", "exe", imports={"kernelbase.dll": ("#7",)})
    doors = _doors(graph, _loaded(_IMAGE, *_SYSTEM_MODULES), image=image)
    assert _process_hit(x64_baseline, doors)["import_present"] is True


def test_an_import_by_ordinal_the_cache_cannot_name_leaves_the_union_incomplete(x64_baseline):
    # an ordinal of a module the cache does not hold, or one no export of it answers to: it may be a door
    for imports in ({"helper.dll": ("#3",)}, {"kernelbase.dll": ("#99",)}):
        graph = _doors_graph(_q("dbghelp.dll", imports=imports))
        doors = _doors(graph, _loaded(_IMAGE, *_SYSTEM_MODULES, _SYS32 + "dbghelp.dll"))
        assert _process_hit(x64_baseline, doors)["import_present"] is None, imports


def test_a_process_of_another_view_than_the_cache_is_not_judged_by_it(x64_baseline):
    # an x64 process on ARM64 runs the x64 side of System32's ARM64X binaries, whose tables the cache did not read
    doors = _doors(_doors_graph(arch="arm64"), _loaded(_IMAGE, *_SYSTEM_MODULES))
    assert _process_hit(x64_baseline, doors)["import_present"] is None


def test_an_image_that_cannot_be_read_or_identified_leaves_the_union_incomplete(x64_baseline):
    table = win32_to_nt.load_table()
    graph, modules = _doors_graph(), _loaded(_IMAGE, *_SYSTEM_MODULES)
    for image_path, image, listed in (
            (_IMAGE, None, modules),                        # its file could not be read
            ("", _image(), modules),                        # its path is not known: which module is it?
            (_IMAGE, _image(), modules[1:]),                # the list does not hold it
            (_IMAGE, _image(), None),                       # the modules could not be listed at all
            (_IMAGE, _image(), []),
            (_IMAGE, _image(), modules + [{"name": "x.dll", "base": 1, "size": 1}])):   # a module without a path
        doors = binary_graph_query.imported_doors(graph, listed, table, view="x64", image_path=image_path,
                                                  image=image)
        assert _process_hit(x64_baseline, doors)["import_present"] is None, (image_path, image, listed)


def test_the_image_is_matched_by_its_path_not_by_its_name(x64_baseline):
    # a sample named kernel32.exe, or one whose path the reader writes in another case
    doors = _doors(_doors_graph(), _loaded("c:\\samples\\SAMPLE.EXE", *_SYSTEM_MODULES))
    assert _process_hit(x64_baseline, doors)["import_present"] is False


def test_why_the_union_is_incomplete_names_the_module(x64_baseline):
    doors, why = binary_graph_query.doors_of_process(
        _doors_graph(), _loaded(_IMAGE, *_SYSTEM_MODULES, "C:\\Samples\\helper.dll"), win32_to_nt.load_table(),
        view="x64", image_path=_IMAGE, image=_image())
    assert doors is None and "C:\\Samples\\helper.dll" in why
    doors, why = binary_graph_query.doors_of_process(
        _doors_graph(), _loaded(_IMAGE, *_SYSTEM_MODULES), win32_to_nt.load_table(), view="x64",
        image_path=_IMAGE, image=_image())
    assert doors is not None and why == ""


# --- the union in the web UI: the pid branch of the stubs route and the detonation stage --------------------------

@pytest.fixture
def doors_host(tdc, monkeypatch, target, sample_dir):
    """An x64 host with the cache of _doors_graph(), and an x64 process of System32 modules and a sample image that
    imports no door: a NtWriteVirtualMemory stub in its private memory. Returns the image path and the builds
    started."""
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26220.5770")
    monkeypatch.setattr(tdc.binary_graph, "host_arch", lambda *a, **k: "x64")
    builds = []
    monkeypatch.setattr(tdc, "_build_binary_graph", lambda build, arch: builds.append((build, arch)))
    os.makedirs(tdc.NTSLEUTH_BASELINE_DIR, exist_ok=True)
    extra = (_q("dbghelp.dll", imports={"kernel32.dll": ("WriteProcessMemory",)}),
             _q("version.dll", imports={"kernel32.dll": ("CloseHandle",)}))
    binary_graph.save_graph(_doors_graph(*extra), os.path.join(tdc.NTSLEUTH_BASELINE_DIR,
                                                         binary_graph.cache_name("26220.5770", "x64")))
    image = sample_dir / "sample.exe"
    image.write_bytes(make_pe(imports=(("kernel32.dll", ("GetLastError",)),)))
    monkeypatch.setattr(tdc, "_image_path_for_pid", lambda pid: str(image))
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    target.reader._m = _loaded(str(image), *_SYSTEM_MODULES)
    return str(image), builds


def test_the_stubs_route_proves_a_bypass_in_a_process_whose_every_module_the_cache_holds(client, doors_host):
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert [h["import_present"] for h in body["hits"]] == [False]
    assert body["doors_complete"] is True and body["doors_note"] == ""
    assert body["evidence"]["findings"][0]["needs_corroboration"] is False


def test_the_stubs_route_keeps_a_hint_when_a_loaded_module_is_unknown(client, target, doors_host):
    target.reader._m = target.reader._m + _loaded("C:\\Program Files\\Hook\\engine.dll")
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert [h["import_present"] for h in body["hits"]] == [None]
    assert body["doors_complete"] is False and "engine.dll" in body["doors_note"]
    assert body["evidence"]["findings"][0]["needs_corroboration"] is True


def test_a_module_loaded_during_the_search_takes_the_proof_back(client, target, doors_host):
    # the scenario the second list exists for (Ruling 36): engine.dll is in the list taken after the search only,
    # loaded while it ran, and the cache does not hold it. The first list is complete and the search proved; only
    # the second list can take that back
    first = target.reader._m
    later = first + _loaded("C:\\Program Files\\Hook\\engine.dll")
    calls = []
    target.reader.modules = lambda: calls.append(1) or (first if len(calls) == 1 else later)
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert len(calls) == 2, "the modules are listed before and after the search"
    assert [h["import_present"] for h in body["hits"]] == [None]
    assert body["doors_complete"] is False and "changed" in body["doors_note"] and "engine.dll" in body["doors_note"]


def test_without_a_cache_the_process_keeps_its_hint_and_no_build_starts(client, tdc, doors_host):
    _, builds = doors_host
    for name in os.listdir(tdc.NTSLEUTH_BASELINE_DIR):
        if name.startswith("binary-graph-"):
            os.remove(os.path.join(tdc.NTSLEUTH_BASELINE_DIR, name))
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert [h["import_present"] for h in body["hits"]] == [None]
    assert body["doors_complete"] is False and "binary graph" in body["doors_note"]
    _join(tdc)
    # a scan does not start minutes of reading System32 under a sample being observed
    assert builds == []


def test_the_detonation_stage_proves_a_bypass_in_the_process_when_the_union_is_complete(tdc, doors_host):
    image, _ = doors_host
    result = tdc._run_syscall_stage(4812, image, [])
    process = result["stubs"]["process"]
    assert [h["import_present"] for h in process["hits"]] == [False]
    assert process["doors_complete"] is True
    [finding] = [f for f in result["evidence"]["findings"] if f["kind"] == "direct_syscall_stub"]
    assert finding["needs_corroboration"] is False


def test_the_detonation_stage_keeps_the_process_hint_when_the_union_is_incomplete(tdc, target, doors_host):
    image, _ = doors_host
    target.reader._m = target.reader._m + _loaded("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll")
    result = tdc._run_syscall_stage(4812, None, [])
    process = result["stubs"]["process"]
    assert [h["import_present"] for h in process["hits"]] == [None]
    assert process["doors_complete"] is False and "clr.dll" in process["doors_note"]


# --- Ruling 31: the denominator covers every module loaded at any point of the search ------------------------------

def _changing(target, later):
    first = target.reader._m
    calls = []
    target.reader.modules = lambda: calls.append(1) or (first if len(calls) == 1 else later(first))
    return calls


def test_a_cached_module_loaded_during_the_search_brings_its_doors_into_the_union(client, target, doors_host):
    # dbghelp arrived while the search ran: its import of WriteProcessMemory was in the address space all the same
    _changing(target, lambda first: first + _loaded(_SYS32 + "dbghelp.dll"))
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert [h["import_present"] for h in body["hits"]] == [True]
    assert body["doors_complete"] is True


def test_a_cached_module_without_a_door_loaded_during_the_search_keeps_the_proof(client, target, doors_host):
    _changing(target, lambda first: first + _loaded(_SYS32 + "version.dll"))
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert [h["import_present"] for h in body["hits"]] == [False]
    assert body["doors_complete"] is True


def test_a_module_gone_by_the_end_of_the_search_still_counts(client, target, doors_host):
    # listed before the search, unloaded by its end: the union is over both lists, not the last one
    calls = []
    first = target.reader._m + _loaded(_SYS32 + "dbghelp.dll")
    target.reader.modules = lambda: calls.append(1) or (first if len(calls) == 1 else first[:-1])
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert [h["import_present"] for h in body["hits"]] == [True]


def test_a_module_list_that_cannot_be_had_after_the_search_takes_the_proof_back(client, target, doors_host):
    _changing(target, lambda first: None)
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert [h["import_present"] for h in body["hits"]] == [None]
    assert body["doors_complete"] is False


# --- Ruling 35: an import by ordinal is named through the cache, in both modes ------------------------------------

def _ordinal_sample(sample_dir, *functions, name="ordinal.exe", module="kernel32.dll"):
    path = sample_dir / name
    path.write_bytes(make_pe(imports=((module, functions),)) + _X64_STUB_0x3A)
    return path


def _file_hit(client, path):
    body = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"}).get_json()
    [hit] = body["hits"]
    return hit, body


def test_a_sample_importing_its_door_by_ordinal_is_not_a_proven_bypass(client, doors_host, sample_dir):
    # kernel32!#157 is WriteProcessMemory in the cache's record of kernel32: the sample holds the door
    hit, body = _file_hit(client, _ordinal_sample(sample_dir, 157))
    assert hit["import_present"] is True
    assert body["doors_complete"] is True


def test_an_import_by_ordinal_no_cache_can_name_allows_no_proof_in_a_file(client, tdc, doors_host, sample_dir):
    for functions, module in (((999,), "kernel32.dll"), ((3,), "helper.dll")):
        hit, body = _file_hit(client, _ordinal_sample(sample_dir, *functions, module=module))
        assert hit["import_present"] is None, (functions, module)
        assert body["doors_complete"] is False and module in body["doors_note"]
    # without a cache, no ordinal can be named at all
    for name in os.listdir(tdc.NTSLEUTH_BASELINE_DIR):
        if name.startswith("binary-graph-"):
            os.remove(os.path.join(tdc.NTSLEUTH_BASELINE_DIR, name))
    hit, body = _file_hit(client, _ordinal_sample(sample_dir, 157, name="again.exe"))
    assert hit["import_present"] is None and body["doors_complete"] is False


def test_an_import_by_ordinal_of_no_door_keeps_the_proof_of_a_file(client, doors_host, sample_dir):
    hit, _ = _file_hit(client, _ordinal_sample(sample_dir, 158))          # kernel32!#158 is CloseHandle
    assert hit["import_present"] is False


def test_a_file_without_imports_by_ordinal_proves_without_a_cache(client, target, sample_dir):
    # nothing to name: the file's denominator is complete whether or not a graph exists
    hit, body = _file_hit(client, _loader(sample_dir, "GetLastError"))
    assert hit["import_present"] is False and body["doors_complete"] is True


def test_the_detonation_stage_names_the_ordinals_of_the_sample_file_and_of_the_image(tdc, doors_host, sample_dir):
    image, _ = doors_host
    with open(image, "wb") as fh:
        fh.write(make_pe(imports=(("kernel32.dll", (157,)),)) + _X64_STUB_0x3A)
    result = tdc._run_syscall_stage(4812, image, [])
    assert [h["import_present"] for h in result["stubs"]["file"]["hits"]] == [True]
    assert [h["import_present"] for h in result["stubs"]["process"]["hits"]] == [True]
    [finding] = [f for f in result["evidence"]["findings"] if f["kind"] == "direct_syscall_stub"]
    assert finding["needs_corroboration"] is True


def test_ordinals_are_named_only_by_a_graph_of_the_importers_view():
    imports = {"kernel32.dll": ("#157", "GetLastError")}
    assert binary_graph_query.name_ordinal_imports(_doors_graph(), imports, view="x64") == (
        {"WriteProcessMemory"}, "")
    for graph, view in ((_doors_graph(arch="arm64"), "x64"), (None, "x64")):
        names, why = binary_graph_query.name_ordinal_imports(graph, imports, view=view)
        assert names is None and why
    # nothing by ordinal needs no graph
    assert binary_graph_query.name_ordinal_imports(None, {"kernel32.dll": ("GetLastError",)}, view="x64") == (set(), "")


def test_the_imports_by_ordinal_of_a_pe_are_read_delay_loaded_ones_included(tdc):
    data = make_pe(imports=(("KERNEL32.dll", (157, "GetLastError")),), delay=(("ws2_32.dll", (115,)),))
    assert tdc._pe_ordinal_imports(data) == {"kernel32.dll": ("#157",), "ws2_32.dll": ("#115",)}
    assert tdc._pe_ordinal_imports(b"not a pe") is None
