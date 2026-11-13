"""The install scripts the tool updates call: -Force, version pins, release markers."""

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FORCE_SCRIPTS = ["capa", "beaconeye", "process-dump", "scanner-tools", "rustinel", "fibratus", "aether", "sysmon"]
MARKER_SCRIPTS = ["capa", "beaconeye", "process-dump", "scanner-tools", "rustinel", "fibratus"]


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def _script(name):
    return _read("scripts", f"install-{name}.ps1")


def _param_block(script):
    m = re.search(r"^param\s*\((.*?)^\)", script, re.S | re.M | re.I)
    assert m, "no param( block"
    return m.group(1)


@pytest.mark.parametrize("name", FORCE_SCRIPTS)
def test_force_switch_in_every_update_script(name):
    script = _script(name)
    assert re.search(r"\[switch\]\s*\$Force\b", _param_block(script))
    # The "already installed" short cut only applies without -Force.
    assert re.search(r"(?m)^\s*\}?\s*(?:if|elseif)\s*\(.*-not\s+\$Force\b.*\)\s*\{", script)


@pytest.mark.parametrize("name", MARKER_SCRIPTS)
def test_release_marker_written(name):
    script = _script(name)
    assert "tdc-release.txt" in script
    assert "Set-Content" in script


def test_pinned_scripts_take_a_version():
    rustinel = _param_block(_script("rustinel"))
    assert re.search(r'\[string\]\$Version\s*=\s*"1\.1\.1"', rustinel)
    fibratus = _param_block(_script("fibratus"))
    assert re.search(r'\[string\]\$Version\s*=\s*"3\.0\.0"', fibratus)
    rizin = _param_block(_script("rizin"))
    assert re.search(r'\$Version\s*=\s*"2\.5\.0"', rizin)
    assert re.search(r'\$PackageSha256\s*=\s*"a04154a03a392dbf5886a629938582f7d23a93636fa0611c3e1c34905b197e69"', rizin)
    assert re.search(r"\[string\]\$RizinVersion\b", rizin)


def test_scanner_tools_only_parameter():
    script = _script("scanner-tools")
    assert "$Only" in _param_block(script)
    assert "ThreatCheck" in script and "DefenderCheck" in script


def test_sysmon_records_etags():
    script = _script("sysmon")
    for needle in ("tdc-source.json", "binary_etag", "config_etag", "-u force"):
        assert needle in script, needle


def test_rustinel_stops_what_holds_the_exe():
    script = _script("rustinel")
    assert re.search(r"Stop-ScheduledTask[^\n]*Rustinel", script)
    assert re.search(r"Stop-Service[^\n]*Rustinel", script)
    assert re.search(r"Stop-Process[^\n]*rustinel", script, re.I)


def test_fibratus_force_reinstalls_the_msi():
    script = _script("fibratus")
    assert re.search(r"Stop-Service[^\n]*fibratus", script)
    assert "/x" in script and "/qn /norestart" in script
    assert "3010" in script and "1641" in script


def test_process_dump_never_regenerates_the_clean_baseline():
    script = _script("process-dump")
    assert re.search(r"if\s*\(Test-Path \$CleanDb\)", script)


def test_scripts_reach_the_vm():
    for name in ("Vagrantfile", "Vagrantfile.utm"):
        assert 'destination: "C:\\\\tdc\\\\scripts"' in _read(name), name
    assert "C:\\tdc\\scripts" in _read("scripts", "deploy-utm.py")
    assert "SCRIPT_FILES" in _read("scripts", "deploy-utm.py")
    assert "C:\\\\tdc\\\\scripts" in _read("Makefile")
    assert "C:\\tdc\\scripts" in _read("make.ps1")
