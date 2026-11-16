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
    assert script.index("is current; configuration updated") < verify
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
    download = script[script.index("# Download Sysmon"):script.index("# Same or older version")]
    assert "SourceEtag" not in download
    # ...and the marker write has its own guard
    assert re.search(r"function Save-SourceEtag \{.*?try \{\s*Set-SourceEtag.*?\} catch", script, re.S)


def test_sysmon_config_refresh_checks_the_exit_code():
    script = _script("sysmon")
    branch = script[script.index("-not $Force) {"):script.index("# Create directory")]
    apply_at = branch.index("& $configExe -c $configPath")
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
    assert re.search(r'foreach \(\$name in @\("Sysmon64a", "Sysmon64"\)\) \{\s*if \(Get-Service -Name \$name', script)
    assert re.search(r'\$installedExe\b', script)
    assert re.search(r'\$uninstallExe\s*=\s*\$installedExe', script)
    assert re.search(r'Uninstall-SysmonBinary\s+-Exe\s+\$uninstallExe', script)
    assert re.search(r'& \$Exe\s+-accepteula\s+-u\s+force', script)
    assert not re.search(r'\$sysmonExe\s+-accepteula\s+-u\s+force', script)


def _sysmon_code():
    # The script without comment lines, so a comment cannot satisfy a check.
    return "\n".join(line for line in _script("sysmon").splitlines() if not line.strip().startswith("#"))


def test_sysmon_compares_installed_and_downloaded_versions():
    code = _sysmon_code()
    assert "FileVersion" in code
    assert re.search(r"Win32_Service|ImagePath|PathName", code)
    assert re.search(r"\$downloadedVersion\s+-le\s+\$installedVersion", code)
    assert "is current; configuration updated" in code
    # the "current" branch applies the config with -c and checks the exit code
    m = re.search(r"is current; configuration updated", code)
    before = code[:m.start()]
    assert re.search(r"-accepteula\s+-c\s+\$configPath", before)
    assert "binary_etag" in code and "config_etag" in code


def test_sysmon_current_branch_comes_before_any_uninstall():
    code = _sysmon_code()
    assert code.index("is current; configuration updated") < code.index("Uninstall-SysmonBinary -Exe $uninstallExe")


def test_sysmon_backs_up_installed_binaries_before_extracting():
    code = _sysmon_code()
    assert re.search(r'\$backupDir\s*=\s*"\$sysmonDir\\backup"', code)
    assert code.index("Backup-RunningSysmon -Installed") < code.index("Expand-Archive")
    assert re.search(r"Copy-Item[^\n]*\$dest|Copy-Item[^\n]*\$dir", code)


def test_sysmon_waits_for_the_uninstall_and_retries_the_install():
    code = _sysmon_code()
    assert "function Wait-SysmonGone" in code
    assert "SysmonDrv" in code
    assert re.search(r"wevtutil(\.exe)?\s+gl\s+Microsoft-Windows-Sysmon/Operational", code)
    assert re.search(r"-lt\s+60|60\s*\)", code)
    assert "function Install-SysmonService" in code
    assert re.search(r"for\s*\(\$attempt\s*=\s*1;\s*\$attempt\s+-le\s+3", code)
    assert re.search(r"Start-Sleep\s+-Seconds\s+10", code)


def test_sysmon_rolls_back_to_the_backed_up_binary():
    code = _sysmon_code()
    assert "New Sysmon failed to install; restored the previous version" in code
    assert re.search(r"Install-SysmonService\s+-Exe\s+\$rollbackExe", code)
    assert re.search(r"\$rollbackExe\s*=\s*Join-Path\s+\(Join-Path\s+\$backupDir\s+\"\$installedVersion\"\)", code)
    assert "rollback" in code.lower() and "Rollback failed" in code


def test_sysmon_script_parses():
    import shutil
    import subprocess
    pwsh = shutil.which("pwsh") or ("/opt/homebrew/bin/pwsh" if os.path.exists("/opt/homebrew/bin/pwsh") else None)
    if not pwsh:
        pytest.skip("pwsh not installed")
    path = os.path.join(ROOT, "scripts", "install-sysmon.ps1")
    cmd = ("$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
           f"'{path}', [ref]$null, [ref]$e); if ($e) {{ $e | ForEach-Object {{ $_.Message }}; exit 1 }}")
    proc = subprocess.run([pwsh, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_sysmon_backup_is_per_version_from_the_running_service_binary():
    code = _sysmon_code()
    fn = re.search(r"function Backup-RunningSysmon \{(.*?)\n\}\n", code, re.S)
    assert fn, "Backup-RunningSysmon missing"
    body = fn.group(1)
    assert "Test-SysmonRunning" in body
    assert "FromService" in body
    assert re.search(r'Join-Path\s+\$backupDir\s+"\$Version"', body)
    # the freshly extracted download is never a backup source
    assert "$sysmonExe" not in body
    assert "Get-ChildItem" not in body
    # the old "copy every tools-dir Sysmon*.exe" backup is gone
    assert not re.search(r'Get-ChildItem[^\n]*Sysmon\*\.exe', code)


def test_sysmon_versions_are_normalised_to_four_parts():
    code = _sysmon_code()
    assert "function ConvertTo-NormalVersion" in code
    assert re.search(r"Math\]::Max\(\$v\.Build,\s*0\)", code)
    assert re.search(r"Math\]::Max\(\$v\.Revision,\s*0\)", code)


def test_sysmon_aborts_on_pending_deletion_before_the_first_uninstall():
    code = _sysmon_code()
    assert "function Get-PendingDeletion" in code
    assert "DeleteFlag" in code
    assert re.search(r"HKLM:\\SYSTEM\\CurrentControlSet\\Services", code)
    assert "reboot required" in code
    assert code.index("$pending = @(Get-PendingDeletion)") < code.index("Uninstall-SysmonBinary -Exe $uninstallExe")
    m = re.search(r"\$pending = @\(Get-PendingDeletion\)\s*\n\s*if \(\$pending\.Count[^\n]*\{(.*?)exit 1", code, re.S)
    assert m and "reboot required" in m.group(1)


def test_sysmon_registers_a_recovery_task_around_the_uninstall():
    code = _sysmon_code()
    assert "TDC-SysmonRecover" in code
    assert "function Register-SysmonRecovery" in code and "function Unregister-SysmonRecovery" in code
    assert "New-ScheduledTaskTrigger -AtStartup" in code
    assert re.search(r'New-ScheduledTaskPrincipal[^\n]*SYSTEM', code)
    assert re.search(r"-accepteula -i", code[code.index("function Register-SysmonRecovery"):code.index("function Unregister-SysmonRecovery")])
    assert "Unregister-ScheduledTask" in code
    # registered before -u force, removed again once Sysmon is verified
    assert code.index("Register-SysmonRecovery -Exe") < code.index("Uninstall-SysmonBinary -Exe $uninstallExe")
    assert code.count("Unregister-SysmonRecovery") >= 3


def test_sysmon_install_verifies_the_running_version():
    code = _sysmon_code()
    assert "function Get-RunningSysmonVersion" in code
    assert re.search(r"function Install-SysmonService \{\s*param\(\[string\]\$Exe,\s*\$ExpectedVersion", code)
    assert re.search(r"Install-SysmonService\s+-Exe\s+\$sysmonExe\s+-ExpectedVersion\s+\$downloadedVersion", code)
    assert re.search(r"Install-SysmonService\s+-Exe\s+\$rollbackExe\s+-ExpectedVersion\s+\$installedVersion", code)
    # binary_etag only when the running version is the downloaded one
    tail = code[code.index("$runningVersion = Get-RunningSysmonVersion"):]
    assert re.search(r"\$runningVersion\s+-eq\s+\$downloadedVersion", tail)


def test_sysmon_uninstalls_with_the_version_matched_backup_copy():
    code = _sysmon_code()
    m = re.search(r"\$uninstallExe\s*=\s*Join-Path\s+\(Join-Path\s+\$backupDir\s+\"\$installedVersion\"\)", code)
    assert m
    assert re.search(r"\$uninstallExe\s*=\s*\$installedExe", code)
    assert code.index("$backupDir") < code.index("$uninstallExe")


def test_sysmon_service_path_is_normalised():
    code = _sysmon_code()
    fn = code[code.index("function Get-ServiceExe"):code.index("function Test-ServiceExists")]
    assert "ExpandEnvironmentVariables" in fn
    assert r"\\\?\?\\" in fn or r"\?\?" in fn
    assert "SystemRoot" in fn


def test_sysmon_retry_uninstall_only_with_force_and_config_uses_service_binary():
    code = _sysmon_code()
    fn = code[code.index("function Install-SysmonService"):code.index("$sysmonSvc = Get-Service -Name $sysmonServiceName")]
    assert re.search(r"if \(\$Force\)\s*\{\s*\[void\]\(Uninstall-SysmonBinary|if \(\$Force\)\s*\{[^}]*Uninstall-SysmonBinary", fn)
    plain = code[code.index("$sysmonSvc = Get-Service -Name $sysmonServiceName"):code.index("New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null\n\n")]
    assert "$sysmonExe -c" not in plain
    assert re.search(r"Get-InstalledSysmon", plain)


def test_sysmon_current_branch_saves_binary_etag_only_for_the_service_binary():
    code = _sysmon_code()
    branch = code[code.index("$downloadedVersion = Get-BinaryVersion"):code.index("is current; configuration updated")]
    assert re.search(r"if \(\$binaryEtag -and \$installedFromService\)", branch)


def test_sysmon_version_parse_takes_the_first_token_not_the_first_char():
    # ('15.22' | Where-Object)[0] is the char '1'; the token list must be wrapped in @()
    code = _sysmon_code()
    assert re.search(r"\$first = @\(\$Text", code)
