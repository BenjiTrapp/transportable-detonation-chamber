"""Syscall stubs carried outside ntdll: found in a file's bytes or in a process's memory."""

import pathlib
import random

import pytest

import memory_evidence
import syscall_baseline
import syscall_scan
import win32_to_nt
from test_syscalls import FakeReader, _fixture

MOV_R10_RCX_MOV_EAX = bytes.fromhex("4c8bd1b8")
SYSCALL = bytes.fromhex("0f05")
# the tail of a Windows 11 x64 stub between the number and the syscall instruction
TEST_SHARED_DATA = bytes.fromhex("f604250803fe7f017503")
SVC_RET = 0xD65F03C0


@pytest.fixture
def x64_baseline():
    return syscall_baseline.parse_baseline(_fixture("x64"), "26220.5770", "x64")


@pytest.fixture
def arm64_baseline():
    return syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")


# the syscalls the curated Win32 to Nt table leads to: NtAllocateVirtualMemory (0x18), NtWriteVirtualMemory
# (0x3A) and NtProtectVirtualMemory (0x50) of the fixture are among them
COVERED = win32_to_nt.load_table().covered


def _x64_stub(number, between=b""):
    return MOV_R10_RCX_MOV_EAX + number.to_bytes(4, "little") + between + SYSCALL


def _svc(number):
    return (0xD4000001 | (number << 5)).to_bytes(4, "little")


def _arm64_stub(number):
    return _svc(number) + SVC_RET.to_bytes(4, "little")


# --- a file's bytes -------------------------------------------------------------------

def test_an_embedded_x64_stub_with_a_valid_number_is_found(x64_baseline):
    sc = x64_baseline.syscalls["NtAllocateVirtualMemory"]
    blob = b"\x90" * 64 + bytes.fromhex("4c8bd1b8") + sc.number.to_bytes(4, "little") \
        + bytes.fromhex("0f05c3") + b"\x90" * 64
    hits = syscall_scan.find_stubs_in_bytes(blob, x64_baseline)
    assert [h["syscall"] for h in hits] == ["NtAllocateVirtualMemory"]
    assert hits[0]["offset"] == 64
    assert hits[0]["number_known"] is True


def test_harmless_bytes_produce_no_hit(x64_baseline):
    assert syscall_scan.find_stubs_in_bytes(b"MZ" + b"\x41" * 4096, x64_baseline) == []


def test_a_number_from_another_build_is_reported_separately(x64_baseline):
    blob = bytes.fromhex("4c8bd1b8") + (0x7FE).to_bytes(4, "little") + bytes.fromhex("0f05")
    hits = syscall_scan.find_stubs_in_bytes(blob, x64_baseline)
    assert hits and hits[0]["number_known"] is False
    assert hits[0]["syscall"] is None


def test_the_hit_describes_the_stub_it_found(x64_baseline):
    blob = b"\xcc" * 5 + _x64_stub(0x3A, TEST_SHARED_DATA) + b"\xc3"
    (hit,) = syscall_scan.find_stubs_in_bytes(blob, x64_baseline)
    assert hit["syscall"] == "NtWriteVirtualMemory"
    assert hit["number"] == 0x3A
    assert hit["module"] == "ntdll.dll"
    assert hit["view"] == "x64"
    assert hit["offset"] == 5
    assert hit["stub_hex"] == _x64_stub(0x3A, TEST_SHARED_DATA).hex()
    assert isinstance(hit["pattern"], str) and hit["pattern"]


def test_a_baseline_stub_as_ntsleuth_recorded_it_is_found(x64_baseline):
    sc = x64_baseline.syscalls["NtProtectVirtualMemory"]
    (hit,) = syscall_scan.find_stubs_in_bytes(b"\x00" * 7 + sc.stub_bytes, x64_baseline)
    assert (hit["syscall"], hit["offset"]) == ("NtProtectVirtualMemory", 7)
    assert sc.stub_bytes.hex().startswith(hit["stub_hex"])


def test_a_win32u_number_resolves_to_its_own_module(x64_baseline):
    (hit,) = syscall_scan.find_stubs_in_bytes(_x64_stub(0x1034), x64_baseline)
    assert (hit["syscall"], hit["module"]) == ("NtUserGetForegroundWindow", "win32u.dll")


def test_an_empty_file_has_no_hit(x64_baseline):
    assert syscall_scan.find_stubs_in_bytes(b"", x64_baseline) == []


def test_a_stub_ending_exactly_at_the_end_of_the_buffer_is_found(x64_baseline):
    (hit,) = syscall_scan.find_stubs_in_bytes(b"\x90" * 9 + _x64_stub(0x18), x64_baseline)
    assert hit["offset"] == 9


@pytest.mark.parametrize("cut", range(1, 10))
def test_a_stub_cut_short_by_the_end_of_the_buffer_is_not_a_hit(x64_baseline, cut):
    assert syscall_scan.find_stubs_in_bytes(_x64_stub(0x18)[:-cut], x64_baseline) == []


def test_the_syscall_instruction_must_follow_the_number_closely(x64_baseline):
    near = _x64_stub(0x18, b"\x90" * 16)
    far = _x64_stub(0x18, b"\x90" * 17)
    assert len(syscall_scan.find_stubs_in_bytes(near, x64_baseline)) == 1
    assert syscall_scan.find_stubs_in_bytes(far, x64_baseline) == []


def test_two_stubs_in_a_row_are_both_found_in_order(x64_baseline):
    blob = _x64_stub(0x18, TEST_SHARED_DATA) + b"\xc3" + _x64_stub(0x3A) + b"\xc3"
    hits = syscall_scan.find_stubs_in_bytes(blob, x64_baseline)
    assert [h["syscall"] for h in hits] == ["NtAllocateVirtualMemory", "NtWriteVirtualMemory"]
    assert hits[0]["offset"] < hits[1]["offset"]


def test_a_prefix_whose_own_syscall_is_missing_does_not_borrow_the_next_stubs(x64_baseline):
    lonely = MOV_R10_RCX_MOV_EAX + (0x18).to_bytes(4, "little") + b"\xc3"
    hits = syscall_scan.find_stubs_in_bytes(lonely + _x64_stub(0x3A), x64_baseline)
    assert [h["syscall"] for h in hits] == ["NtWriteVirtualMemory"]


def test_the_same_stub_twice_is_two_hits(x64_baseline):
    blob = _x64_stub(0x50) + b"\x90" * 8 + _x64_stub(0x50)
    assert len(syscall_scan.find_stubs_in_bytes(blob, x64_baseline)) == 2


def test_other_code_that_resembles_a_stub_is_not_one(x64_baseline):
    # real non-malicious shapes: the same moves without a syscall, a Linux-style syscall
    # without the Windows register move, and a stub whose head a hook has overwritten
    sc = x64_baseline.syscalls["NtWriteVirtualMemory"]
    moves_only = MOV_R10_RCX_MOV_EAX + (5).to_bytes(4, "little") + b"\xc3" + b"\xcc" * 20
    linux_style = bytes.fromhex("b83a000000") + SYSCALL + b"\xc3"
    hooked = bytes.fromhex("e9") + (0x1234).to_bytes(4, "little") + sc.stub_bytes[5:]
    blob = b"\xcc" * 8 + moves_only + linux_style + hooked
    assert syscall_scan.find_stubs_in_bytes(blob, x64_baseline) == []


def test_ordinary_text_and_data_produce_no_hit(x64_baseline, arm64_baseline):
    text = (pathlib.Path(syscall_scan.__file__).read_bytes()
            + pathlib.Path(memory_evidence.__file__).read_bytes()) * 3
    assert syscall_scan.find_stubs_in_bytes(text, x64_baseline) == []
    assert syscall_scan.find_stubs_in_bytes(text, arm64_baseline) == []


def test_random_bytes_produce_no_hit(x64_baseline, arm64_baseline):
    data = random.Random(6).randbytes(2_000_000)
    assert syscall_scan.find_stubs_in_bytes(data, x64_baseline) == []
    assert syscall_scan.find_stubs_in_bytes(data, arm64_baseline) == []


def test_an_arm64_stub_is_found_with_the_number_of_its_svc(arm64_baseline):
    blob = b"\x00" * 8 + _arm64_stub(0x3A) + b"\x00" * 8
    (hit,) = syscall_scan.find_stubs_in_bytes(blob, arm64_baseline)
    assert (hit["syscall"], hit["number"], hit["offset"]) == ("NtWriteVirtualMemory", 0x3A, 8)
    assert hit["view"] == "arm64"
    assert hit["stub_hex"] == _arm64_stub(0x3A).hex()


def test_an_arm64_svc_needs_its_ret_and_a_word_aligned_place(arm64_baseline):
    no_ret = _svc(0x3A) + b"\x1f\x20\x03\xd5"
    unaligned = b"\x00\x00" + _arm64_stub(0x3A)
    assert syscall_scan.find_stubs_in_bytes(no_ret, arm64_baseline) == []
    assert syscall_scan.find_stubs_in_bytes(unaligned, arm64_baseline) == []


def test_an_arm64_number_from_another_build_is_reported_separately(arm64_baseline):
    (hit,) = syscall_scan.find_stubs_in_bytes(_arm64_stub(0x7FE), arm64_baseline)
    assert (hit["number_known"], hit["syscall"], hit["number"]) == (False, None, 0x7FE)


def test_the_stub_shape_of_one_view_is_not_searched_with_the_other(x64_baseline, arm64_baseline):
    assert syscall_scan.find_stubs_in_bytes(_arm64_stub(0x3A), x64_baseline) == []
    assert syscall_scan.find_stubs_in_bytes(_x64_stub(0x3A), arm64_baseline) == []


def test_every_baseline_view_has_a_search_shape():
    assert set(syscall_scan.STUB_SHAPES) == {"x64", "arm64"}


# --- the import table -------------------------------------------------------------------

def test_a_stub_without_the_matching_import_weighs_more(x64_baseline):
    sc = x64_baseline.syscalls["NtAllocateVirtualMemory"]
    blob = bytes.fromhex("4c8bd1b8") + sc.number.to_bytes(4, "little") + bytes.fromhex("0f05")
    without = syscall_scan.find_stubs_in_bytes(blob, x64_baseline, expanded_imports=set(), covered=COVERED)
    with_imp = syscall_scan.find_stubs_in_bytes(
        blob, x64_baseline, imports={"NtAllocateVirtualMemory"})
    assert without[0]["import_present"] is False
    assert with_imp[0]["import_present"] is True
    a = memory_evidence.score(memory_evidence.from_direct_stubs(without, "s.exe"))["score"]
    b = memory_evidence.score(memory_evidence.from_direct_stubs(with_imp, "s.exe"))["score"]
    assert a > b


def test_the_import_of_the_zw_name_counts_as_the_import(x64_baseline):
    (hit,) = syscall_scan.find_stubs_in_bytes(
        _x64_stub(0x18), x64_baseline, imports={"ZwAllocateVirtualMemory"})
    assert hit["import_present"] is True


def test_another_function_in_the_expanded_table_is_not_the_import(x64_baseline):
    (hit,) = syscall_scan.find_stubs_in_bytes(
        _x64_stub(0x18), x64_baseline, expanded_imports={"NtWriteVirtualMemory", "VirtualAlloc"},
        covered=COVERED)
    assert hit["import_present"] is False


def test_the_expanded_table_speaks_only_for_the_syscalls_it_covers(x64_baseline):
    assert {"NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory"} <= COVERED
    (hit,) = syscall_scan.find_stubs_in_bytes(
        _x64_stub(0x18), x64_baseline, expanded_imports=set(),
        covered={"NtWriteVirtualMemory"})
    assert hit["import_present"] is None


def test_without_an_import_table_the_import_is_unknown_not_absent(x64_baseline):
    (hit,) = syscall_scan.find_stubs_in_bytes(_x64_stub(0x18), x64_baseline)
    assert hit["import_present"] is None
    (hit,) = syscall_scan.find_stubs_in_bytes(
        _x64_stub(0x7FE), x64_baseline, expanded_imports=set(), covered=COVERED)
    assert hit["import_present"] is None


def test_a_raw_import_table_can_show_a_presence_but_never_an_absence(x64_baseline):
    # a sample that calls the Win32 wrapper does not import the Nt name: against its raw
    # table the stub looks unimported, while the documented path is right there
    raw = {"VirtualAllocEx", "kernel32.dll"}
    (hit,) = syscall_scan.find_stubs_in_bytes(_x64_stub(0x18), x64_baseline, imports=raw)
    assert hit["import_present"] is None
    (hit,) = syscall_scan.find_stubs_in_bytes(_x64_stub(0x18), x64_baseline, imports=set())
    assert hit["import_present"] is None
    (hit,) = syscall_scan.find_stubs_in_bytes(
        _x64_stub(0x18), x64_baseline, imports={"NtAllocateVirtualMemory"})
    assert hit["import_present"] is True


def test_a_raw_table_never_unlocks_the_weight_of_a_proven_bypass(x64_baseline):
    raw = {"VirtualAllocEx"}
    hits = syscall_scan.find_stubs_in_bytes(_x64_stub(0x18), x64_baseline, imports=raw)
    (finding,) = memory_evidence.from_direct_stubs(hits, "s.exe")
    assert finding["needs_corroboration"] is True
    assert memory_evidence.score([finding])["score"] < \
        memory_evidence.KINDS["direct_syscall_stub"]["weight"]


def test_the_wrapper_in_the_expanded_table_leads_down_to_the_stub(x64_baseline):
    # the caller has run the table: VirtualAllocEx became NtAllocateVirtualMemory
    (hit,) = syscall_scan.find_stubs_in_bytes(
        _x64_stub(0x18), x64_baseline, expanded_imports={"VirtualAllocEx", "NtAllocateVirtualMemory"},
        covered=COVERED)
    assert hit["import_present"] is True


def test_the_expanded_table_cannot_be_passed_by_position(x64_baseline):
    # a caller holding a raw set must not land in the strong slot by accident
    with pytest.raises(TypeError):
        syscall_scan.find_stubs_in_bytes(_x64_stub(0x18), x64_baseline, set(), set())


def _stub_findings(x64_baseline, imports=None, number=0x18, expanded=None):
    hits = syscall_scan.find_stubs_in_bytes(
        _x64_stub(number), x64_baseline, imports=imports, expanded_imports=expanded,
        covered=None if expanded is None else COVERED)
    return memory_evidence.from_direct_stubs(hits, "s.exe")


def test_a_proven_bypass_carries_the_full_weight_of_the_kind(x64_baseline):
    (finding,) = _stub_findings(x64_baseline, expanded=set())
    assert finding["kind"] == "direct_syscall_stub"
    assert finding["base_weight"] == memory_evidence.KINDS["direct_syscall_stub"]["weight"]
    scored = memory_evidence.score([finding])
    assert scored["findings"][0]["confidence"] == 1.0
    assert scored["score"] == memory_evidence.KINDS["direct_syscall_stub"]["weight"]


def test_a_stub_that_is_also_imported_is_held_with_less_confidence(x64_baseline):
    (finding,) = _stub_findings(x64_baseline, {"NtAllocateVirtualMemory"})
    assert finding["kind"] == "direct_syscall_stub"
    item = memory_evidence.score([finding])["findings"][0]
    assert 0 < item["confidence"] < 1.0


def test_an_unknown_import_table_does_not_prove_the_bypass(x64_baseline):
    (unknown,) = _stub_findings(x64_baseline)
    (absent,) = _stub_findings(x64_baseline, expanded=set())
    assert memory_evidence.score([unknown])["score"] < memory_evidence.score([absent])["score"]


def test_a_number_of_another_build_scores_as_a_hint_and_says_so(x64_baseline):
    (finding,) = _stub_findings(x64_baseline, number=0x7FE, expanded=set())
    assert finding["kind"] == "direct_syscall_stub"
    assert finding["number_known"] is False
    assert "0x7fe" in finding["detail"].lower()
    assert memory_evidence.score([finding])["score"] < \
        memory_evidence.score(_stub_findings(x64_baseline, expanded=set()))["score"]


def test_a_second_source_lifts_a_hint_to_full_confidence(x64_baseline):
    (finding,) = _stub_findings(x64_baseline, {"NtAllocateVirtualMemory"})
    other = memory_evidence.MemoryFinding(
        source="pe-sieve", kind="disk_mem_diff", process="s.exe", identity=("x",))
    scored = memory_evidence.score([finding, other])
    stub = next(f for f in scored["findings"] if f["kind"] == "direct_syscall_stub")
    assert stub["confidence"] == 1.0


def _lonely_finding():
    """A finding of another scanner that needs a second opinion and has none."""
    return memory_evidence.MemoryFinding(
        source="aether", kind="thread_staged_rw", process="s.exe", identity=("x",))


def _confidence_of(scored, kind):
    return next(f for f in scored["findings"] if f["kind"] == kind)["confidence"]


def test_a_stub_hint_does_not_lift_an_uncorroborated_finding_of_another_source(x64_baseline):
    (hint,) = _stub_findings(x64_baseline, {"NtAllocateVirtualMemory"})
    alone = memory_evidence.score([_lonely_finding()])
    beside = memory_evidence.score([hint, _lonely_finding()])
    assert _confidence_of(alone, "thread_staged_rw") == memory_evidence.UNCORROBORATED
    assert _confidence_of(beside, "thread_staged_rw") == memory_evidence.UNCORROBORATED
    other = next(f for f in beside["findings"] if f["kind"] == "thread_staged_rw")
    assert "corroborated_by" not in other


@pytest.mark.parametrize("imports, expanded, number", [
    (None, None, 0x18),                        # import table unknown
    ({"NtAllocateVirtualMemory"}, None, 0x18),  # imported as well
    (None, set(), 0x7FE),                      # a number this build does not have
])
def test_no_kind_of_hint_vouches_for_another_source(x64_baseline, imports, expanded, number):
    (hint,) = _stub_findings(x64_baseline, imports, number=number, expanded=expanded)
    assert hint["needs_corroboration"] is True and hint["may_corroborate"] is False
    beside = memory_evidence.score([hint, _lonely_finding()])
    assert _confidence_of(beside, "thread_staged_rw") == memory_evidence.UNCORROBORATED


def test_a_proven_bypass_still_vouches_for_another_source(x64_baseline):
    (proven,) = _stub_findings(x64_baseline, expanded=set())
    assert "may_corroborate" not in proven
    beside = memory_evidence.score([proven, _lonely_finding()])
    assert _confidence_of(beside, "thread_staged_rw") == 1.0


def test_no_other_scanner_opts_out_of_corroborating():
    results = {"syscall_scan": {"build": "b", "view": "x64", "deviations": [
        {"state": "patched", "name": "NtClose", "target_owner": "private"}]}}
    findings = memory_evidence.collect(results, process="s.exe")
    findings.append(_lonely_finding())
    assert findings and all("may_corroborate" not in f for f in findings)


def test_the_finding_key_holds_no_address(x64_baseline):
    def key(offset):
        blob = b"\x90" * offset + _x64_stub(0x18)
        hits = syscall_scan.find_stubs_in_bytes(blob, x64_baseline, expanded_imports=set(), covered=COVERED)
        return memory_evidence.from_direct_stubs(hits, "s.exe")[0]["key"]
    assert key(10) == key(900)


def test_the_finding_key_names_the_syscall_and_the_process(x64_baseline):
    def key(number, process="s.exe"):
        hits = syscall_scan.find_stubs_in_bytes(_x64_stub(number), x64_baseline, expanded_imports=set(),
                                                covered=COVERED)
        return memory_evidence.from_direct_stubs(hits, process)[0]["key"]
    assert key(0x18) != key(0x3A)
    assert key(0x18) != key(0x18, "other.exe")
    assert key(0x7FE) != key(0x7FF)


def test_copies_of_one_stub_are_one_finding_that_counts_them(x64_baseline):
    blob = _x64_stub(0x50) + b"\x90" * 8 + _x64_stub(0x50) + _x64_stub(0x3A)
    hits = syscall_scan.find_stubs_in_bytes(blob, x64_baseline, expanded_imports=set(), covered=COVERED)
    findings = memory_evidence.from_direct_stubs(hits, "s.exe")
    by_syscall = {f["syscall"]: f for f in findings}
    assert set(by_syscall) == {"NtProtectVirtualMemory", "NtWriteVirtualMemory"}
    assert by_syscall["NtProtectVirtualMemory"]["copies"] == 2
    assert by_syscall["NtWriteVirtualMemory"]["copies"] == 1


def _copy(offset, imported, own_export=None):
    hit = {"syscall": "NtWriteVirtualMemory", "number": 0x3A, "offset": offset, "view": "arm64",
           "pattern": "p", "stub_hex": "00", "import_present": imported, "number_known": True,
           "module": "ntdll.dll"}
    if own_export is not None:
        hit["own_export"] = own_export
    return hit


@pytest.mark.parametrize("answers, group", [
    ((False, True), True), ((True, False), True), ((None, True), True), ((False, None, True), True),
    ((False, None), None), ((None, False), None), ((False, False), False)])
def test_a_group_takes_the_weakest_claim_among_its_copies(answers, group):
    # Ruling 72: a group may not claim more than its most forgiving copy, whichever comes first
    hits = [_copy(0x10 * i, answer) for i, answer in enumerate(answers)]
    (finding,) = memory_evidence.from_direct_stubs(hits, "s.dll")
    assert finding["import_present"] is group
    assert finding["needs_corroboration"] is (group is not False)


def test_the_sample_files_copies_decide_over_its_process_copies():
    # the ordering runs over one source: a process copy answers for every loaded module (kernelbase imports the Nt
    # functions), never for the sample, so it must not switch off the file's proof in a detonation
    process = dict(_copy(0, True), address=0x1F0000)
    del process["offset"]
    for others in ([process], [dict(process, import_present=None)]):
        (finding,) = memory_evidence.from_direct_stubs([_copy(0x400, False, False)] + others, "s.exe")
        assert finding["import_present"] is False and finding["needs_corroboration"] is False
    # without a file copy, the process copies decide among themselves
    (finding,) = memory_evidence.from_direct_stubs([dict(process, import_present=False), process], "s.exe")
    assert finding["import_present"] is True


def test_a_stub_the_file_exports_under_its_own_name_says_so(x64_baseline):
    # Ruling 73: the fact is per hit, the rescue fired for it; no threshold over the file
    (finding,) = memory_evidence.from_direct_stubs([_copy(0x8d0, True, True), _copy(0x8e0, True, True)], "ntdll.dll")
    assert finding["detail"] == ("NtWriteVirtualMemory stub the file exports under its own name: the module's own "
                                 "code, not a stub carried past the documented path")
    (finding,) = memory_evidence.from_direct_stubs([_copy(0x8d0, True, True), _copy(0x900, False, False)], "s.dll")
    assert finding["import_present"] is True
    # Ruling 76: only some copies are export bodies, so the sentence says that, and never calls the others the
    # module's own code; it names what it counts (the copies in the file)
    assert finding["detail"] == ("NtWriteVirtualMemory stub: 1 of the 2 copies in the file are the bodies of its own "
                                 "export under that name and the others are not, so this is a hint rather than a "
                                 "proof; a file that exports a syscall stub under an Nt name deserves a look")
    assert "own code" not in finding["detail"]
    # every file copy an export body, but a copy in process memory beside them (a detonation): no word for that one
    process = dict(_copy(0, True), address=0x1F0000)
    del process["offset"]
    (finding,) = memory_evidence.from_direct_stubs([_copy(0x8d0, True, True), _copy(0x8e0, True, True), process],
                                                   "s.exe")
    assert finding["copies"] == 3
    assert finding["detail"] == ("NtWriteVirtualMemory stub the file exports under its own name, in each of its 2 "
                                 "copies in the file; a copy in process memory cannot be attributed to that export")
    # imported by the table, not exported: the old sentence
    (finding,) = memory_evidence.from_direct_stubs([_copy(0x8d0, True, False)], "s.dll")
    assert finding["detail"] == "NtWriteVirtualMemory stub carried by the sample, which imports it as well"


def test_a_process_hit_gives_its_address_to_the_finding(x64_baseline):
    hit = {"syscall": "NtClose", "number": 0xF, "address": 0x1F0000, "view": "x64",
           "pattern": "p", "stub_hex": "00", "import_present": False, "number_known": True,
           "module": "ntdll.dll"}
    (finding,) = memory_evidence.from_direct_stubs([hit], "s.exe")
    assert finding["address"] == 0x1F0000


@pytest.mark.parametrize("hits", [None, [], "x", [None], [{}]])
def test_malformed_or_empty_hits_make_no_finding(hits):
    assert memory_evidence.from_direct_stubs(hits, "s.exe") == []


def test_a_stub_finding_is_suppressed_by_the_host_baseline(x64_baseline, tmp_path):
    findings = _stub_findings(x64_baseline, expanded=set())
    baseline = memory_evidence.MemoryBaseline(str(tmp_path / "baseline.json"))
    baseline.add(findings)
    scored = memory_evidence.score(findings, baseline)
    assert scored["score"] == 0 and scored["suppressed_count"] == 1


# --- a process's memory -----------------------------------------------------------------

MEM_FREE = 0x10000
PAGE_RX, PAGE_RW, PAGE_RWX, PAGE_NOACCESS, PAGE_GUARD_RX = 0x20, 0x04, 0x40, 0x01, 0x120
PRIVATE_BASE = 0x1F0000


def _region(type_, protect, path=None, state=syscall_scan.MEM_COMMIT):
    return syscall_scan.Region(state, type_, path, 0, 0, protect)


def _space(*mapped, view="x64"):
    """A process from `(base, data, region)` triples, the gaps between them free."""
    ranges, regions, at = [], [], 0
    for base, data, region in sorted(mapped, key=lambda m: m[0]):
        size = (len(data) + 0xFFF) & ~0xFFF
        if base > at:
            regions.append((at, base - at, _region(0, 0, state=MEM_FREE)))
        ranges.append((base, bytearray(data.ljust(size, b"\x00"))))
        regions.append((base, size, region))
        at = base + size
    regions.append((at, syscall_scan._USER_SPACE_END - at, _region(0, 0, state=MEM_FREE)))
    return FakeReader([], ranges, regions, view=view)


def _like(source, cls=FakeReader, **kw):
    """The process of `source`, as `cls` with the given changes."""
    kw = {"regions": source._regions, "view": source._view, "build": source._build, **kw}
    return cls(source._m, source._ranges, **kw)


def _private(protect=PAGE_RX):
    return _region(syscall_scan.MEM_PRIVATE, protect)


def test_a_stub_in_private_executable_memory_is_found_at_its_address(x64_baseline):
    data = b"\x90" * 0x40 + _x64_stub(0x3A, TEST_SHARED_DATA) + b"\xc3"
    hits = syscall_scan.find_stubs_in_process(
        _space((PRIVATE_BASE, data, _private())), x64_baseline)
    assert [h["syscall"] for h in hits] == ["NtWriteVirtualMemory"]
    assert hits[0]["address"] == PRIVATE_BASE + 0x40
    assert "offset" not in hits[0]
    assert hits[0]["number_known"] is True
    assert hits.partial is False


@pytest.mark.parametrize("protect", [PAGE_RX, 0x10, PAGE_RWX, 0x80])
def test_every_executable_protection_is_searched(x64_baseline, protect):
    hits = syscall_scan.find_stubs_in_process(
        _space((PRIVATE_BASE, _x64_stub(0x18), _private(protect))), x64_baseline)
    assert len(hits) == 1


@pytest.mark.parametrize("protect", [PAGE_RW, 0x02, PAGE_NOACCESS, 0])
def test_memory_that_cannot_execute_is_not_searched(x64_baseline, protect):
    hits = syscall_scan.find_stubs_in_process(
        _space((PRIVATE_BASE, _x64_stub(0x18), _private(protect))), x64_baseline)
    assert hits == [] and hits.partial is False


def test_a_file_backed_image_is_not_searched_even_when_it_holds_a_stub(x64_baseline):
    image = _region(syscall_scan.MEM_IMAGE, PAGE_RX, "\\Device\\HarddiskVolume3\\Windows\\vendor.dll")
    reader = _space((0x7FF800000000, _x64_stub(0x18), image))
    assert syscall_scan.find_stubs_in_process(reader, x64_baseline) == []


def test_a_mapped_view_of_a_file_is_not_searched_but_a_pagefile_backed_one_is(x64_baseline):
    data = _x64_stub(0x18)
    named = _region(syscall_scan.MEM_MAPPED, PAGE_RX, "\\Device\\HarddiskVolume3\\x.dat")
    anonymous = _region(syscall_scan.MEM_MAPPED, PAGE_RX)
    assert syscall_scan.find_stubs_in_process(_space((0x2000000, data, named)), x64_baseline) == []
    hits = syscall_scan.find_stubs_in_process(_space((0x2000000, data, anonymous)), x64_baseline)
    assert [h["address"] for h in hits] == [0x2000000]


def test_a_region_with_no_protection_known_is_never_searched(x64_baseline):
    unknown = syscall_scan.Region(syscall_scan.MEM_COMMIT, syscall_scan.MEM_PRIVATE, None)
    assert syscall_scan.find_stubs_in_process(
        _space((PRIVATE_BASE, _x64_stub(0x18), unknown)), x64_baseline) == []


class _Spy(FakeReader):
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.touched = []

    def read(self, addr, size):
        self.touched.append((addr, size))
        return super().read(addr, size)


def test_a_guard_page_is_never_read(x64_baseline):
    # reading a guard page raises it: the scan would change the process it watches
    source = _space((PRIVATE_BASE, _x64_stub(0x18), _region(syscall_scan.MEM_PRIVATE, PAGE_GUARD_RX)))
    reader = _like(source, _Spy)
    assert syscall_scan.find_stubs_in_process(reader, x64_baseline) == []
    assert reader.touched == []


def test_only_the_regions_that_qualify_are_read(x64_baseline):
    data = _x64_stub(0x18)
    source = _space((PRIVATE_BASE, data, _private()),
                    (0x400000, data, _private(PAGE_RW)),
                    (0x7FF800000000, data, _region(syscall_scan.MEM_IMAGE, PAGE_RX, "\\D\\a.dll")))
    reader = _like(source, _Spy)
    hits = syscall_scan.find_stubs_in_process(reader, x64_baseline)
    assert [h["address"] for h in hits] == [PRIVATE_BASE]
    assert all(PRIVATE_BASE <= addr < PRIVATE_BASE + 0x1000 for addr, _ in reader.touched)


def test_two_regions_each_with_a_stub_give_two_hits_in_address_order(x64_baseline):
    reader = _space((0x3000000, _x64_stub(0x3A), _private()),
                    (PRIVATE_BASE, _x64_stub(0x18), _private(PAGE_RWX)))
    hits = syscall_scan.find_stubs_in_process(reader, x64_baseline)
    assert [(h["address"], h["syscall"]) for h in hits] == [
        (PRIVATE_BASE, "NtAllocateVirtualMemory"), (0x3000000, "NtWriteVirtualMemory")]


@pytest.mark.parametrize("shift", [-26, -20, -10, -1, 0, 1])
def test_a_stub_across_a_read_boundary_is_found_exactly_once(x64_baseline, monkeypatch, shift):
    monkeypatch.setattr(syscall_scan, "_CHUNK", 0x1000)
    stub = _x64_stub(0x18, TEST_SHARED_DATA)
    at = 0x1000 + shift
    data = bytearray(0x3000)
    data[at:at + len(stub)] = stub
    hits = syscall_scan.find_stubs_in_process(
        _space((PRIVATE_BASE, bytes(data), _private())), x64_baseline)
    assert [h["address"] for h in hits] == [PRIVATE_BASE + at]


def test_an_arm64_process_is_searched_with_the_arm64_shape(arm64_baseline, monkeypatch):
    monkeypatch.setattr(syscall_scan, "_CHUNK", 0x1000)
    data = bytearray(0x3000)
    data[0xFFC:0xFFC + 8] = _arm64_stub(0x3A)
    hits = syscall_scan.find_stubs_in_process(
        _space((PRIVATE_BASE, bytes(data), _private()), view="arm64"), arm64_baseline)
    assert [(h["address"], h["syscall"]) for h in hits] == [(PRIVATE_BASE + 0xFFC, "NtWriteVirtualMemory")]


def test_a_region_that_cannot_be_read_makes_the_scan_partial_not_clean(x64_baseline):
    source = _space((PRIVATE_BASE, _x64_stub(0x18), _private()))
    reader = _like(source, cut=PRIVATE_BASE)
    hits = syscall_scan.find_stubs_in_process(reader, x64_baseline)
    assert hits == [] and hits.partial is True
    assert "not read" in hits.note


def test_an_unreadable_region_does_not_hide_the_readable_ones(x64_baseline):
    class Broken(FakeReader):
        def read(self, addr, size):
            return None if addr == PRIVATE_BASE else super().read(addr, size)
    source = _space((PRIVATE_BASE, _x64_stub(0x18), _private()),
                    (0x3000000, _x64_stub(0x3A), _private()))
    reader = _like(source, Broken)
    hits = syscall_scan.find_stubs_in_process(reader, x64_baseline)
    assert [h["address"] for h in hits] == [0x3000000]
    assert hits.partial is True


def test_a_failed_region_query_makes_the_scan_partial(x64_baseline):
    source = _space((PRIVATE_BASE, _x64_stub(0x18), _private()))
    regions = [r for r in source._regions if r[0] < PRIVATE_BASE + 0x1000]
    reader = _like(source, regions=regions)
    hits = syscall_scan.find_stubs_in_process(reader, x64_baseline)
    assert [h["address"] for h in hits] == [PRIVATE_BASE]
    assert hits.partial is True
    assert "region" in hits.note


def test_a_process_whose_memory_cannot_be_walked_is_partial(x64_baseline):
    hits = syscall_scan.find_stubs_in_process(
        FakeReader([], [], [], view="x64"), x64_baseline)
    assert hits == [] and hits.partial is True


def test_a_clean_process_reports_what_it_searched(x64_baseline):
    reader = _space((PRIVATE_BASE, b"\x90" * 100, _private()),
                    (0x400000, b"\x00" * 100, _private(PAGE_RW)))
    hits = syscall_scan.find_stubs_in_process(reader, x64_baseline)
    assert hits == [] and hits.partial is False
    assert hits.regions_searched == 1


def test_the_process_import_table_is_applied(x64_baseline):
    reader = _space((PRIVATE_BASE, _x64_stub(0x18), _private()))
    (hit,) = syscall_scan.find_stubs_in_process(reader, x64_baseline, expanded_imports=set(), covered=COVERED)
    assert hit["import_present"] is False
    (hit,) = syscall_scan.find_stubs_in_process(reader, x64_baseline)
    assert hit["import_present"] is None
    (hit,) = syscall_scan.find_stubs_in_process(reader, x64_baseline, imports={"VirtualAllocEx"})
    assert hit["import_present"] is None


def test_a_process_of_another_view_or_build_is_refused(x64_baseline):
    other_view = _space((PRIVATE_BASE, _x64_stub(0x18), _private()), view="arm64")
    with pytest.raises(syscall_scan.ScanRefused):
        syscall_scan.find_stubs_in_process(other_view, x64_baseline)
    source = _space((PRIVATE_BASE, _x64_stub(0x18), _private()))
    other_build = _like(source, build="26100.1")
    with pytest.raises(syscall_scan.ScanRefused):
        syscall_scan.find_stubs_in_process(other_build, x64_baseline)
    assert other_build.reads == 0


def test_the_region_a_reader_reports_carries_where_it_lies_and_how_it_is_protected():
    reader = _space((PRIVATE_BASE, b"\x00" * 10, _private()))
    region = reader.region(PRIVATE_BASE + 5)
    assert (region.base, region.size, region.protect) == (PRIVATE_BASE, 0x1000, PAGE_RX)
