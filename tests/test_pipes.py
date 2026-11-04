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
