"""Named pipe signature catalog and name normalization."""

import json

import pipe_analysis
from pipe_analysis import (canonical_name, load_signatures, looks_random,
                           match_signature, normalize_for_key)


def test_canonical_name():
    for name in (r"\\.\pipe\msagent_12", "msagent_12", r"\msagent_12"):
        assert canonical_name(name) == r"\msagent_12"
    assert canonical_name(r"\\.\PIPE\MSSE-1-server") == r"\MSSE-1-server"


def test_normalize_for_key():
    assert normalize_for_key("status_4a3f9c") == r"\status_*"
    assert normalize_for_key("MSSE-1234-server") == r"\msse-*-server"
    assert normalize_for_key("{3F2504E0-4F89-11D3-9A0C-0305E82C3301}") == r"\*"


def _family(name, sigs):
    hit = match_signature(name, sigs)
    return hit["family"] if hit else None


def test_signature_catalog_matches_defaults():
    sigs = load_signatures(None)
    for name in (r"\msagent_5b", r"\postex_ab12", r"\status_33",
                 r"\MSSE-4242-server", r"\postex_ssh_1a"):
        assert _family(name, sigs) == "Cobalt Strike", name
    assert _family(r"\PSEXESVC", sigs) == "PsExec"
    for name in (r"\paexec_x", r"\RemCom_communicaton", r"\csexecsvc"):
        assert _family(name, sigs) == "PAExec/RemCom/CSExec", name
    assert match_signature(r"\lsass", sigs) is None
    assert match_signature(r"\mojo.123.456", sigs) is None


def test_catalog_entries_are_well_formed_and_skip_svcctl():
    sigs = load_signatures(None)
    assert sigs
    for sig in sigs:
        assert set(sig) >= {"family", "pattern", "match", "weight", "note"}
        assert sig["match"] in ("prefix", "exact", "contains", "regex")
        assert sig["family"] and sig["note"]
    assert match_signature(r"\svcctl", sigs) is None


def test_invalid_regex_entry_is_skipped(tmp_path):
    path = tmp_path / "sigs.json"
    path.write_text(json.dumps([
        {"family": "Broken", "pattern": "(", "match": "regex", "weight": 1.0, "note": "bad"},
        {"family": "Good", "pattern": r"\good_", "match": "prefix", "weight": 2.0, "note": "ok"},
    ]))
    sigs = load_signatures(str(path))
    assert [s["family"] for s in sigs] == ["Good"]
    assert _family(r"\GOOD_1", sigs) == "Good"


def test_looks_random():
    assert looks_random(r"\a8f3c2e9b7d1f4e6") is True
    assert looks_random(r"\docker_engine") is False
    assert looks_random(r"\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}") is True


def test_module_has_default_catalog_path():
    assert pipe_analysis.DEFAULT_SIGNATURES_PATH.endswith("pipe_signatures.json")


def test_signatures_are_json_serializable():
    sigs = load_signatures(None)
    json.dumps(sigs)
    json.dumps(match_signature(r"\MSSE-1-server", sigs))


def test_prefix_pattern_without_backslash_is_canonicalized(tmp_path):
    path = tmp_path / "sigs.json"
    path.write_text(json.dumps([
        {"family": "CS", "pattern": "postex_", "match": "prefix", "weight": 4.0, "note": "n"},
    ]))
    sigs = load_signatures(str(path))
    assert _family(r"\postex_1", sigs) == "CS"
    assert _family(r"\\.\pipe\POSTEX_1", sigs) == "CS"


def test_bad_weight_and_non_dict_entries_are_skipped(tmp_path, capsys):
    path = tmp_path / "sigs.json"
    path.write_text(json.dumps([
        "not a dict",
        {"family": "Bad", "pattern": r"\bad", "match": "exact", "weight": "high", "note": "n"},
        {"family": "Good", "pattern": r"\good", "match": "exact", "weight": "2.5", "note": "n"},
    ]))
    sigs = load_signatures(str(path))
    assert [s["family"] for s in sigs] == ["Good"]
    assert sigs[0]["weight"] == 2.5
    out = capsys.readouterr().out
    assert out.count("[pipe_analysis]") >= 2


def test_normalize_keeps_english_hex_words():
    for word in (r"\feedback", r"\dbaccess", r"\cafe"):
        assert normalize_for_key(word) == word
    assert normalize_for_key("status_4a3f9c") == r"\status_*"
    assert normalize_for_key("MSSE-1234-server") == r"\msse-*-server"
    assert normalize_for_key("{3F2504E0-4F89-11D3-9A0C-0305E82C3301}") == r"\*"


def test_sysmon_installer_switches_pipeevent_to_exclude():
    import os
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "scripts", "install-sysmon.ps1"), encoding="utf-8") as fh:
        script = fh.read()

    # Existing PipeEvent elements (the include-mode block) are removed.
    assert re.search(r"SelectNodes\([^)]*PipeEvent", script)
    assert "RemoveChild" in script
    assert 'onmatch="exclude"' in script and "<PipeEvent" in script
    assert 'onmatch="include"' not in script.split("<PipeEvent", 1)[1].split("</PipeEvent>", 1)[0]

    block = script.split('<PipeEvent onmatch="exclude">', 1)[1].split("</PipeEvent>", 1)[0]
    rules = re.findall(r'<Rule groupRelation="and">(.*?)</Rule>', block, re.S)
    assert rules
    for rule in rules:
        assert '<Image condition="end with">' in rule
        assert "<PipeName" in rule
    pairs = {(re.search(r"<Image[^>]*>([^<]+)</Image>", r).group(1),
              re.search(r"<PipeName[^>]*>([^<]+)</PipeName>", r).group(1)) for r in rules}
    for image in ("chrome.exe", "msedge.exe"):
        assert (image, r"\mojo.") in pairs
        assert (image, r"\crashpad_") in pairs
    for pipe in (r"\lsass", r"\ntsvcs", r"\srvsvc", r"\wkssvc"):
        assert ("svchost.exe", pipe) in pairs
    assert any(img == "MsMpEng.exe" for img, _ in pairs)
    # No rule may exclude by pipe name alone.
    assert not re.search(r"<PipeEvent onmatch=\"exclude\">\s*<PipeName", script)

    # Post-processing applies to both install paths: before -c and before -i.
    calls = [m.start() for m in re.finditer(r"Set-PipeEventExclude\b", script)]
    assert len(calls) >= 3  # definition + two call sites
    assert script.index("-c $configPath") > calls[1]
    assert script.rindex("-i $configPath") > calls[-1]

    m = re.search(r"wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:(\d+)", script)
    assert m and int(m.group(1)) >= 536870912
