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


@pytest.mark.parametrize("name", ["capa", "beaconeye", "process-dump", "scanner-tools"])
def test_overwrites_fail_loudly(name):
    """A locked exe must not count as replaced: no marker, and -Force exits non-zero."""
    script = _script(name)
    for m in re.finditer(r"(?m)^[^#\n]*\b(?:Copy-Item|Move-Item)\b[^\n]*$", script):
        line = m.group(0)
        if "-Destination" in line and ("$binDir" in line or "$capaInstallDir" in line or "BinDir" in line
                                       or "$bin.Path" in line):
            assert "-ErrorAction Stop" in line, line
    assert re.search(r"\$Force[^\n]*(?:\{[^}]*)?exit 1", script)


@pytest.mark.parametrize("name,exe", [("beaconeye", "BeaconEye"), ("scanner-tools", "ThreatCheck"),
                                      ("scanner-tools", "DefenderCheck")])
def test_source_build_does_not_count_the_old_exe(name, exe):
    script = _script(name)
    assert f"{exe}_build" in script
    # The old exe in the install dir must not be what the build check looks at.
    assert not re.search(rf"dotnet publish[^\n]*-o \$(?:tcBinDir|dcBinDir|binDir)\b", script)


def test_fibratus_force_failure_is_reported():
    script = _script("fibratus")
    # The stale marker is removed before the old MSI goes.
    assert script.index("Remove-Item \"$fibratusInstallDir\\tdc-release.txt\"") < script.index("Uninstall-FibratusMsi\n}")
    # A failed MSI install under -Force ends with exit 1, before the marker or "complete".
    fail = re.search(r"if \(\$Force -and \(\$process\.ExitCode -notin 0, 3010, 1641\)\) \{.*?exit 1", script, re.S)
    assert fail
    assert fail.start() < script.index("tdc-release.txt\" -Value", script.index("Installing Fibratus MSI"))


def test_sysmon_force_failure_is_not_an_update():
    script = _script("sysmon")
    verify = script.index("# Verify installation")
    # -Force with a service that is not running ends with exit 1
    fail = re.search(r"if \(\$Force -and -not \$sysmonRunning\) \{.*?exit 1", script, re.S)
    assert fail and fail.start() > verify
    # The ETags are recorded only after that check, and only for a running service
    for key in ("binary_etag", "config_etag"):
        calls = [m.start() for m in re.finditer(r'Save-SourceEtag -Key "%s"' % key, script)]
        assert calls, key
        assert any(c > fail.end() for c in calls), key
    # Nothing in the download steps writes the marker (a marker failure is no download failure)
    assert "\n    Set-SourceEtag -Key" not in script
    download = script[script.index("# Download Sysmon"):verify]
    assert "SourceEtag" not in download
    # ...and the marker write has its own guard
    assert re.search(r"function Save-SourceEtag \{.*?try \{\s*Set-SourceEtag.*?\} catch", script, re.S)


def test_sysmon_config_refresh_checks_the_exit_code():
    script = _script("sysmon")
    branch = script[script.index("-not $Force) {"):script.index("# Create directory")]
    apply_at = branch.index("& $sysmonExe -c $configPath")
    assert apply_at < branch.index("$LASTEXITCODE") < branch.index('Save-SourceEtag -Key "config_etag"')
    assert re.search(r"if \(\$configExit -ne 0\)", branch)


def test_sysmon_force_keeps_the_existing_config_when_the_download_fails():
    script = _script("sysmon")
    section = script[script.index("# Download SwiftOnSecurity sysmon config"):script.index("# Reinstall:")]
    # downloaded to a temp file, moved into place only on success
    assert "-OutFile $configTmp" in section and "-OutFile $configPath" not in section
    assert re.search(r"Move-Item -Path \$configTmp -Destination \$configPath -Force -ErrorAction Stop", section)
    assert re.search(r"if \(\$Force -and \(Test-Path \$configPath\)\) \{[^}]*keeping the existing", section)
    # the minimal config is the fallback of the else branch only
    assert section.index("keeping the existing") < section.index("$minimalConfig = @\"")
    assert re.search(r"\} else \{\s*\n\s*Write-Host \"\[!\] Config download failed, using minimal config", section)


def test_logging_script_enables_the_log_sources():
    script = _read("scripts", "configure-logging.ps1")
    assert "EnableScriptBlockLogging" in script and "EnableModuleLogging" in script
    assert "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell" in script
    assert "ScriptBlockLogging" in script and "ModuleLogging" in script
    assert re.search(r"ModuleNames", script)
    assert "wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:268435456" in script
    assert "-LogAllowed True" in script and "-LogBlocked True" in script
    assert "-LogMaxSizeKilobytes 32767" in script
    assert "%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log" in script
    assert "exit 0" in script


def test_logging_script_is_provisioned_before_the_services():
    for name in ("Vagrantfile", "Vagrantfile.utm"):
        text = _read(name)
        assert 'path: "scripts/configure-logging.ps1"' in text, name
        assert text.index("configure-logging.ps1") < text.index("configure-services.ps1"), name
    setup = _read("scripts", "setup-macos-utm.sh")
    assert setup.index('"configure-logging.ps1"') < setup.index('"configure-services.ps1"')


def test_logging_script_reaches_an_existing_vm_through_every_deploy_path():
    assert "configure-logging.ps1" in _read("scripts", "deploy-utm.py")
    assert "configure-logging.ps1" in _read("Makefile")
    assert "configure-logging.ps1" in _read("make.ps1")


def test_logging_script_parses():
    import shutil
    import subprocess
    pwsh = shutil.which("pwsh") or ("/opt/homebrew/bin/pwsh" if os.path.exists("/opt/homebrew/bin/pwsh") else None)
    if not pwsh:
        pytest.skip("pwsh not installed")
    path = os.path.join(ROOT, "scripts", "configure-logging.ps1")
    cmd = ("$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
           f"'{path}', [ref]$null, [ref]$e); if ($e) {{ $e | ForEach-Object {{ $_.Message }}; exit 1 }}")
    proc = subprocess.run([pwsh, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr


ARCH_SCRIPTS = ["sysmon", "fibratus", "rustinel", "rizin", "hunt-sleeping-beacons"]
REGISTRY_ARCH = r"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"


def test_no_script_decides_arm64_on_the_process_environment_alone():
    # The web UI runs as emulated x64 Python; its children inherit PROCESSOR_ARCHITECTURE=AMD64.
    scripts_dir = os.path.join(ROOT, "scripts")
    for fname in sorted(os.listdir(scripts_dir)):
        if not fname.endswith(".ps1"):
            continue
        text = _read("scripts", fname)
        assert not re.search(r'\$env:PROCESSOR_ARCHITECTURE\s+-eq\s+"ARM64"', text, re.I), fname


@pytest.mark.parametrize("name", ARCH_SCRIPTS)
def test_arm64_detected_from_the_registry(name):
    script = _script(name)
    assert "$isArm64" in script
    assert re.search(REGISTRY_ARCH, script, re.I)
    assert "PROCESSOR_ARCHITEW6432" in script
    assert re.search(r"\$isArm64\s*=\s*\(\$osArch\s+-eq\s+\"ARM64\"\)", script)


def test_every_script_with_isarm64_uses_the_registry_lookup():
    scripts_dir = os.path.join(ROOT, "scripts")
    for fname in sorted(os.listdir(scripts_dir)):
        if fname.endswith(".ps1"):
            text = _read("scripts", fname)
            if "$isArm64" in text:
                assert re.search(REGISTRY_ARCH, text, re.I), fname


def test_sysmon_force_uninstalls_with_the_binary_of_the_installed_service():
    script = _script("sysmon")
    assert re.search(r'Get-Service -Name "Sysmon64a"', script)
    assert re.search(r'\$installedExe\b', script)
    assert re.search(r'\$installedExe\s+-accepteula\s+-u\s+force', script)
    assert not re.search(r'\$sysmonExe\s+-accepteula\s+-u\s+force', script)
