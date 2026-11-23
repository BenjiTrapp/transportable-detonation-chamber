"""The install scripts the tool updates call: -Force, version pins, release markers."""

import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FORCE_SCRIPTS = ["capa", "beaconeye", "process-dump", "scanner-tools", "rustinel", "fibratus", "aether", "sysmon",
                 "ntsleuth"]
MARKER_SCRIPTS = ["capa", "beaconeye", "process-dump", "scanner-tools", "rustinel", "fibratus", "ntsleuth"]


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


ARCH_SCRIPTS = ["sysmon", "fibratus", "rustinel", "rizin", "hunt-sleeping-beacons", "ntsleuth"]
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


# --- install-ntsleuth.ps1 ---------------------------------------------------

def _function_body(script, name):
    m = re.search(r"(?m)^function %s\b[^\n]*\{\n(.*?)^\}" % re.escape(name), script, re.S)
    assert m, f"no function {name}"
    return m.group(1)


def test_install_ntsleuth_takes_force_and_version():
    script = _script("ntsleuth")
    params = _param_block(script)
    assert re.search(r"\[switch\]\s*\$Force\b", params) and re.search(r"\[string\]\s*\$Version\b", params)
    assert "checksums.txt" in script


def test_ntsleuth_keeps_the_release_names_and_installs_both_views_on_arm64():
    script = _script("ntsleuth")
    # the release ships no plain ntsleuth.exe; Task 7 calls ntsleuth-<view>.exe
    assert "ntsleuth.exe" not in script
    assert re.search(r'\$Views\s*=\s*@\("arm64",\s*"x64"\)', script)
    assert re.search(r'\$Views\s*=\s*@\("x64"\)', script)
    assert 'ntsleuth-$view.exe' in script
    # the OS architecture comes from the registry: a child of an emulated x64 process sees AMD64 in its environment
    assert re.search(r"Session Manager\\Environment", script) and "PROCESSOR_ARCHITECTURE" in script


def test_ntsleuth_stops_on_a_checksum_it_cannot_confirm_before_installing_anything():
    script = _script("ntsleuth")
    assert "exit 1" in _function_body(script, "Stop-Install")
    copy = re.search(r"(?m)^[^#\n]*\bCopy-Item\b[^\n]*\$InstallDir[^\n]*$", script)
    assert copy and "-ErrorAction Stop" in copy.group(0)
    for needle in ("SHA-256 mismatch", "no SHA-256 for"):
        at = script.index(needle)
        # the refusal is a call to Stop-Install, and it comes before the first byte reaches C:\tools\ntsleuth
        assert "Stop-Install" in script[at - 200:at + 400], needle
        assert at < copy.start(), needle
    # nothing downloaded survives a refusal
    assert re.search(r"Get-FileHash[^\n]*-Algorithm SHA256", script)
    assert "Remove-Item $Staging" in _function_body(script, "Stop-Install")


def test_ntsleuth_marker_follows_the_self_test_and_precedes_the_baselines():
    script = _script("ntsleuth")
    marker = script.index('Set-Content -Path "$InstallDir\\tdc-release.txt"')
    # a failed self-test leaves no marker, so the updater keeps offering the update
    assert script.index('"--lookup", "NtCreateProcess"') < marker
    assert script.index("if (-not $selfTestOk) {") < marker
    # the baselines do not gate it: they are stored after it, and nothing of them is in front of it
    assert marker < script.index("[IO.File]::WriteAllText") and marker < script.index("Move-Item -Path \"$target.tmp\"")
    assert "Test-Baseline $view" not in script[:marker].split("function Test-Baseline")[-1].split("# --- Self-test")[-1]
    # the marker of the old release goes before its binaries are replaced
    assert script.index('Remove-Item "$InstallDir\\tdc-release.txt"') < script.index("Copy-Item")
    # the tag is the first line, which is all the updater reads
    assert re.search(r"\$markerLines\s*=\s*@\(\$Tag\)", script)
    assert "sha256:" in script


def test_ntsleuth_only_the_baseline_steps_after_the_self_test_may_warn_instead_of_fail():
    script = _script("ntsleuth")
    installed = script.index("installed to $InstallDir")
    before = script[:installed]
    # what ends in error before the install: download, checksum, copy
    for needle in ("Download of $file failed", "SHA-256 mismatch for", "has no SHA-256 for", "Copying to $InstallDir failed"):
        assert needle in before, needle
    assert "exit 1" in _function_body(script, "Stop-Install")
    # a verified binary that will not extract or look a syscall up is an install failure, with or without -Force
    verdict = script.index("if (-not $selfTestOk) {")
    marker = script.index('Set-Content -Path "$InstallDir\\tdc-release.txt"')
    block = script[verdict:script.index("\n}\n", verdict)]
    assert "exit 1" in block and "no marker is written" in block
    assert installed < verdict < marker and "$Force" not in block
    # the baseline steps after the marker can only warn, and the script ends in 0
    after = script[marker:]
    assert "Stop-Install" not in after and not re.search(r"(?m)^[^#\n]*\bexit 1\b", after)
    assert after.rstrip().endswith("exit 0")


def _powershell_function(name):
    import shutil
    import subprocess
    pwsh = shutil.which("pwsh") or ("/opt/homebrew/bin/pwsh" if os.path.exists("/opt/homebrew/bin/pwsh") else None)
    if not pwsh:
        pytest.skip("pwsh not installed")
    return pwsh, _function_body(_script("ntsleuth"), name)


def test_ntsleuth_fingerprint_tells_the_views_apart_and_ignores_the_metadata():
    import subprocess
    pwsh, body = _powershell_function("Get-ViewFingerprint")
    cmd = ("function Get-ViewFingerprint([string]$Json) {\n" + body + "}\n"
           "function J($rva, $stub, $ms) { '{\"metadata\":{\"extraction_time_ms\":' + $ms + '},\"syscalls\":[{\"name\":\"A\",\"rva\":' + $rva "
           "+ ',\"stub_bytes\":\"' + $stub + '\"}]}' }\n"
           "$a = Get-ViewFingerprint (J 5392 'a10900d4c0035fd6' 402)\n"
           "$b = Get-ViewFingerprint (J 5392 'a10900d4c0035fd6' 977)\n"
           "$c = Get-ViewFingerprint (J 5392 '4c8bd1b8c0000000' 402)\n"
           "$d = Get-ViewFingerprint (J 5400 'a10900d4c0035fd6' 402)\n"
           "\"same=$($a -eq $b) stub=$($a -ne $c) rva=$($a -ne $d) empty=[$(Get-ViewFingerprint '{}')]\"")
    proc = subprocess.run([pwsh, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=60)
    assert proc.stdout.strip() == "same=True stub=True rva=True empty=[]", proc.stdout + proc.stderr


def test_ntsleuth_says_so_loudly_when_the_two_arm64_baselines_are_the_same():
    script = _script("ntsleuth")
    at = script.index("BASELINES IDENTICAL")
    block = script[script.rindex("if ($isArm64 -and", 0, at):at + 600]
    assert "$extractions.ContainsKey(\"arm64\")" in block and "$extractions.ContainsKey(\"x64\")" in block
    assert re.search(r"\$armPrint\s+-eq\s+\$x64Print", block)
    # red, not a quiet note; and a comparison that could not be made is said too
    assert "-ForegroundColor Red" in script[at - 10:at + 400] and "could not be compared" in script
    # the baselines of an ARM64 install are compared in memory, from what NTSleuth printed, not from file names
    assert "Get-ViewFingerprint $extractions" in script


def test_ntsleuth_baselines_are_named_and_placed_as_the_web_ui_looks_for_them():
    import syscall_baseline
    script = _script("ntsleuth")
    app = _read("webui", "app.py")
    assert 'NTSLEUTH_DIR = r"C:\\tools\\ntsleuth"' in app
    assert re.search(r'\$InstallDir\s*=\s*"C:\\tools\\ntsleuth"', script)
    assert 'NTSLEUTH_BASELINE_DIR = os.path.join(NTSLEUTH_DIR, "baseline")' in app
    assert re.search(r'\$BaselineDir\s*=\s*"\$InstallDir\\baseline"', script)
    # <build> is CurrentBuildNumber.UBR, as _current_os_build writes it
    assert "CurrentBuildNumber" in script and "UBR" in script
    assert 'f"{number}.{revision}"' in app and '"$number.$ubr"' in script
    template = re.search(r'"(\$BaselineDir\\ntsleuth-\$build-\$view\.json)"', script)
    assert template, "the baseline file name is not built from build and view"
    name = template.group(1).split("\\")[-1].replace("$build", "26220.5770").replace("$view", "arm64")
    assert name == "ntsleuth-26220.5770-arm64.json"
    assert syscall_baseline.parse_baseline_name(name) == ("26220.5770", "arm64")
    # the extraction is run as the web UI runs it, from the install dir and in NTSleuth's own output folder
    assert '"--auto-params", "--format", "json"' in script and '"--no-symbols"' in script
    assert '"$InstallDir\\output\\syscalls.json"' in script and '"output\\syscalls.json"' not in script


def test_ntsleuth_baseline_of_a_run_without_symbols_says_so_in_the_form_the_web_ui_reads():
    import syscall_baseline
    script = _script("ntsleuth")
    prefix = '{"symbols":false,'
    assert prefix in script
    # NTSleuth's own top level is an object ({"metadata", "modules", "os_info", "syscalls"}, keys sorted)
    raw = json.dumps({"metadata": {}, "syscalls": [{
        "name": "NtCreateProcess", "module": "ntdll.dll", "syscall_number": 192, "rva": 7236,
        "is_true_syscall": True, "stub_bytes": "011800d4c0035fd6"}]}, indent=2, sort_keys=True)
    marked = json.loads(prefix + raw.lstrip()[1:])
    parsed = syscall_baseline.parse_baseline(marked, "26220.5770", "arm64")
    assert parsed.symbols is False and "NtCreateProcess" in parsed.syscalls
    assert syscall_baseline.parse_baseline(json.loads(raw), "26220.5770", "arm64").symbols is True


def test_ntsleuth_self_test_needs_a_number_not_an_exit_code():
    script = _script("ntsleuth")
    # --lookup exits 0 when the name is missing or the JSON unreadable, so the output has to be read
    assert '"--lookup", "NtCreateProcess"' in script
    assert re.search(r"\\\[Number\\\]", script)
    assert "x1b" in script, "the output is coloured with escape codes; they sit inside the label"
    # every view gets the name it will be looked up under, checked on disk afterwards
    body = _function_body(script, "Test-Baseline")
    assert "Get-Item" in body and ".Length -gt 0" in body
    assert re.search(r"-notmatch '\^ntsleuth-", body)


def test_ntsleuth_is_provisioned_in_all_three_places_before_the_web_ui():
    for name, marker in (("Vagrantfile", "scripts/install-ntsleuth.ps1"), ("Vagrantfile.utm", "scripts/install-ntsleuth.ps1"),
                         ("scripts/setup-macos-utm.sh", '"install-ntsleuth.ps1"')):
        text = _read(*name.split("/"))
        assert text.count(marker) == 1, name
        webui = "scripts/install-webui.ps1" if name.startswith("Vagrantfile") else '"install-webui.ps1"'
        assert text.index(marker) < text.index(webui), name


def test_ntsleuth_script_parses():
    import shutil
    import subprocess
    pwsh = shutil.which("pwsh") or ("/opt/homebrew/bin/pwsh" if os.path.exists("/opt/homebrew/bin/pwsh") else None)
    if not pwsh:
        pytest.skip("pwsh not installed")
    path = os.path.join(ROOT, "scripts", "install-ntsleuth.ps1")
    cmd = ("$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
           f"'{path}', [ref]$null, [ref]$e); if ($e) {{ $e | ForEach-Object {{ $_.Message }}; exit 1 }}")
    proc = subprocess.run([pwsh, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
