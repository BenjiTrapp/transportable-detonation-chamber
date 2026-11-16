# install-sysmon.ps1
# Installs Sysmon (System Monitor) from Sysinternals with comprehensive logging config
#
# Sysmon provides:
#   - Process creation/termination with full command lines
#   - Network connection logging
#   - File creation time changes
#   - Driver/image loading
#   - Raw access read (disk)
#   - Registry modifications
#   - DNS query logging
#   - Pipe/WMI event monitoring
#   - Clipboard capture
#
# Uses SwiftOnSecurity/sysmon-config for tuned event filtering
# Events logged to: Microsoft-Windows-Sysmon/Operational
#
# Run as Administrator
#
# Parameters:
#   -Force   reinstall the Sysmon binary even if the service runs (used by the
#            tool updates): Sysmon64[a].exe -u force, then -accepteula -i <config>.
#            Without -Force and with Sysmon running, only the config is refreshed.
#
# The ETag of every download (Sysmon.zip, the SwiftOnSecurity config) is kept
# in C:\tools\sysmon\tdc-source.json as {"binary_etag": "...", "config_etag": "..."},
# so the tool updates can tell whether Sysinternals or the config changed.

param(
    [switch]$Force
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Sysmon ===" -ForegroundColor Cyan

# Detect architecture - ARM64 uses Sysmon64a.exe, x86_64 uses Sysmon64.exe
# OS architecture: the registry holds the real value; the process environment
# says AMD64 for children of an emulated x64 process (e.g. the web UI's Python)
$osArch = $null
try {
    $osArch = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PROCESSOR_ARCHITECTURE -ErrorAction Stop).PROCESSOR_ARCHITECTURE
} catch { $osArch = $null }
if (-not $osArch) { $osArch = $env:PROCESSOR_ARCHITEW6432 }
if (-not $osArch) { $osArch = $env:PROCESSOR_ARCHITECTURE }
$isArm64 = ($osArch -eq "ARM64")
$sysmonDir = "C:\tools\sysmon"
if ($isArm64) {
    $sysmonExe = "$sysmonDir\Sysmon64a.exe"
    $sysmonServiceName = "Sysmon64a"
    Write-Host "[*] ARM64 detected - will use Sysmon64a.exe (native ARM64 build)" -ForegroundColor Yellow
} else {
    $sysmonExe = "$sysmonDir\Sysmon64.exe"
    $sysmonServiceName = "Sysmon64"
}
$configPath = "$sysmonDir\sysmonconfig.xml"
$sourceMarker = "$sysmonDir\tdc-source.json"

# The upstream config only logs a short list of pipe names (include mode), so
# almost no EID 17/18 events are written. Replace every PipeEvent filter with
# one exclude-mode group that drops known benign noise. Every rule combines
# Image AND PipeName so a sample cannot hide by reusing a benign pipe name.
function Set-PipeEventExclude {
    param([string]$Path)
    $pipeGroup = @'
<RuleGroup name="" groupRelation="or">
  <PipeEvent onmatch="exclude">
    <Rule groupRelation="and"><Image condition="end with">\chrome.exe</Image><PipeName condition="begin with">\mojo.</PipeName></Rule>
    <Rule groupRelation="and"><Image condition="end with">\chrome.exe</Image><PipeName condition="begin with">\crashpad_</PipeName></Rule>
    <Rule groupRelation="and"><Image condition="end with">\msedge.exe</Image><PipeName condition="begin with">\mojo.</PipeName></Rule>
    <Rule groupRelation="and"><Image condition="end with">\msedge.exe</Image><PipeName condition="begin with">\crashpad_</PipeName></Rule>
    <Rule groupRelation="and"><Image condition="is">C:\Windows\System32\lsass.exe</Image><PipeName condition="begin with">\lsass</PipeName></Rule>
    <Rule groupRelation="and"><Image condition="is">C:\Windows\System32\services.exe</Image><PipeName condition="begin with">\ntsvcs</PipeName></Rule>
    <Rule groupRelation="and"><Image condition="is">C:\Windows\System32\svchost.exe</Image><PipeName condition="begin with">\srvsvc</PipeName></Rule>
    <Rule groupRelation="and"><Image condition="is">C:\Windows\System32\svchost.exe</Image><PipeName condition="begin with">\wkssvc</PipeName></Rule>
    <Rule groupRelation="and"><Image condition="begin with">C:\ProgramData\Microsoft\Windows Defender\Platform\</Image><Image condition="end with">\MsMpEng.exe</Image><PipeName condition="begin with">\</PipeName></Rule>
  </PipeEvent>
</RuleGroup>
'@
    try {
        [xml]$cfg = Get-Content -Path $Path -Raw
        foreach ($node in @($cfg.SelectNodes("//PipeEvent"))) {
            $parent = $node.ParentNode
            [void]$parent.RemoveChild($node)
            if ($parent.LocalName -eq "RuleGroup" -and -not $parent.HasChildNodes) {
                [void]$parent.ParentNode.RemoveChild($parent)
            }
        }
        $fragment = New-Object System.Xml.XmlDocument
        $fragment.LoadXml($pipeGroup)
        $filtering = $cfg.SelectSingleNode("/Sysmon/EventFiltering")
        [void]$filtering.AppendChild($cfg.ImportNode($fragment.DocumentElement, $true))
        $cfg.Save($Path)
        Write-Host "[+] PipeEvent switched to exclude mode" -ForegroundColor Green
    } catch {
        Write-Host "[!] PipeEvent post-processing failed - pipe events will not be logged: $_" -ForegroundColor Red
    }
}

# The upstream config logs EID 3 (NetworkConnect) only for images under C:\Users, C:\ProgramData and the like, for
# a list of LOLBins and for a few ports. The FIREWALL tab needs the connection of every download it is to catch:
# System32's curl.exe, the BITS service (svchost.exe), and TDC's own python (the tdc-anomaly net) are not on that
# list, so a curl or BITS download could never become a finding. Add them to every include-mode NetworkConnect
# filter; a config without one (exclude mode, the minimal config) logs them already.
# Each comes as a Rule with Initiated=true: EID 3 is written for accepted connections too, and the reader takes
# every EID 3 as outbound, so without it the analyst's own browser on port 9000 would become TDC python flows
# tagged tdc-anomaly, and RDP or SMB into the VM svchost flows.
function Set-NetworkConnectIncludes {
    param([string]$Path)
    $wanted = @(
        @{ Name = 'TDC firewall tab: curl'; Condition = 'image'; Value = 'curl.exe' },
        @{ Name = 'TDC firewall tab: python'; Condition = 'image'; Value = 'python.exe' },
        @{ Name = 'TDC firewall tab: pythonw'; Condition = 'image'; Value = 'pythonw.exe' },
        @{ Name = 'TDC firewall tab: svchost (BITS)'; Condition = 'is'; Value = 'C:\Windows\System32\svchost.exe' }
    )
    try {
        [xml]$cfg = Get-Content -Path $Path -Raw
        $includes = @($cfg.SelectNodes("//NetworkConnect[@onmatch='include']"))
        foreach ($node in $includes) {
            # an earlier version added plain Image entries, which also logged inbound connections
            foreach ($old in @($node.SelectNodes("Image[@name='TDC firewall tab']"))) { [void]$node.RemoveChild($old) }
            foreach ($w in $wanted) {
                $have = @($node.SelectNodes("Rule") | Where-Object { $_.GetAttribute('name') -eq $w.Name })
                if ($have.Count -gt 0) { continue }
                $rule = $cfg.CreateElement('Rule')
                $rule.SetAttribute('name', $w.Name)
                $rule.SetAttribute('groupRelation', 'and')
                $image = $cfg.CreateElement('Image')
                $image.SetAttribute('condition', $w.Condition)
                $image.InnerText = $w.Value
                [void]$rule.AppendChild($image)
                $initiated = $cfg.CreateElement('Initiated')
                $initiated.SetAttribute('condition', 'is')
                $initiated.InnerText = 'true'
                [void]$rule.AppendChild($initiated)
                [void]$node.AppendChild($rule)
            }
        }
        $cfg.Save($Path)
        if ($includes.Count -gt 0) {
            Write-Host "[+] NetworkConnect also logs the outbound connections of curl.exe, python.exe and svchost.exe (BITS)" -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] NetworkConnect post-processing failed - curl and BITS downloads may never become a FIREWALL finding: $_" -ForegroundColor Red
    }
}

function Set-SysmonLogSize {
    # 512 MB so pipe events do not rotate out short detonations
    wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:536870912
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Could not set Sysmon log size to 512 MB (wevtutil exit $LASTEXITCODE)" -ForegroundColor Red
    } else {
        Write-Host "[+] Sysmon log size set to 512 MB" -ForegroundColor Green
    }
}

# ETag of a download response, or "" when the server sent none.
function Get-ETag {
    param($Response)
    try {
        $value = $Response.Headers["ETag"]
        if ($value -is [array]) { $value = $value[0] }
        if ($value) { return [string]$value }
    } catch { }
    return ""
}

# Records the ETag of a download in tdc-source.json, keeping the other key.
function Set-SourceEtag {
    param([string]$Key, [string]$Value)
    $record = [ordered]@{ binary_etag = ""; config_etag = "" }
    if (Test-Path $sourceMarker) {
        try {
            $old = Get-Content -Path $sourceMarker -Raw | ConvertFrom-Json
            foreach ($name in @("binary_etag", "config_etag")) {
                if ($old.PSObject.Properties[$name]) { $record[$name] = [string]$old.$name }
            }
        } catch { }
    }
    $record[$Key] = $Value
    New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null
    Set-Content -Path $sourceMarker -Value ($record | ConvertTo-Json) -Encoding ASCII
}

# A marker write failure is a warning of its own, never a failed install.
function Save-SourceEtag {
    param([string]$Key, [string]$Value)
    try {
        Set-SourceEtag -Key $Key -Value $Value
    } catch {
        Write-Host "[!] Could not record the $Key in tdc-source.json: $_" -ForegroundColor Yellow
    }
}

# A version as 4 parts (15.22 -> 15.22.0.0), so -1 for a missing part never skews a comparison.
function ConvertTo-NormalVersion {
    param([string]$Text)
    try {
        if (-not $Text) { return $null }
        $first = @($Text -replace ',', '.' -split '\s+' | Where-Object { $_ })[0]
        $v = [version]$first
        return (New-Object System.Version -ArgumentList $v.Major, $v.Minor, ([Math]::Max($v.Build, 0)), ([Math]::Max($v.Revision, 0)))
    } catch { return $null }
}

# FileVersion of a binary as a normalised [version], or $null.
function Get-BinaryVersion {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $null }
    try {
        return (ConvertTo-NormalVersion -Text ([string](Get-Item -Path $Path).VersionInfo.FileVersion))
    } catch { return $null }
}

# The executable a Sysmon service runs (ImagePath, e.g. C:\Windows\Sysmon64a.exe), or $null.
function Get-ServiceExe {
    param([string]$ServiceName)
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        if ($svc -and $svc.PathName) {
            $path = ([string]$svc.PathName).Trim()
            if ($path -match '^"([^"]+)"') { $path = $Matches[1] }
            elseif ($path -match '^(.+?\.exe)') { $path = $Matches[1] }
            $path = $path -replace '^\\\?\?\\', ''
            if ($path -match '^\\SystemRoot\\') { $path = $env:SystemRoot + $path.Substring(11) }
            $path = [Environment]::ExpandEnvironmentVariables($path)
            if (Test-Path $path) { return $path }
        }
    } catch { }
    return $null
}

# The installed Sysmon: service name, the binary the service runs, and whether that
# binary came from the service ImagePath (FromService) or only from the tools dir.
function Get-InstalledSysmon {
    foreach ($name in @("Sysmon64a", "Sysmon64")) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
            $exe = Get-ServiceExe -ServiceName $name
            $fromService = [bool]$exe
            if (-not $exe) {
                $exe = "$sysmonDir\$name.exe"
                if (-not (Test-Path $exe)) { $exe = $null }
            }
            return [pscustomobject]@{ Name = $name; Exe = $exe; FromService = $fromService }
        }
    }
    return $null
}

function Test-ServiceExists {
    param([string]$Name)
    & sc.exe query $Name 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Test-SysmonRunning {
    foreach ($name in @("Sysmon64a", "Sysmon64")) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { return $true }
    }
    return $false
}

# Version of the Sysmon that runs now: the process image, else the service ImagePath binary.
function Get-RunningSysmonVersion {
    foreach ($name in @("Sysmon64a", "Sysmon64")) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not ($svc -and $svc.Status -eq "Running")) { continue }
        try {
            $proc = Get-Process -Name $name -ErrorAction Stop | Select-Object -First 1
            $v = ConvertTo-NormalVersion -Text ([string]$proc.MainModule.FileVersionInfo.FileVersion)
            if ($v) { return $v }
        } catch { }
        return (Get-BinaryVersion -Path (Get-ServiceExe -ServiceName $name))
    }
    return $null
}

# Services or driver whose deletion waits for a reboot (DeleteFlag = 1).
function Get-PendingDeletion {
    $pending = @()
    foreach ($name in @("Sysmon64a", "Sysmon64", "SysmonDrv")) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        try {
            $flag = (Get-ItemProperty -Path $key -Name DeleteFlag -ErrorAction Stop).DeleteFlag
            if ($flag -eq 1) { $pending += $name }
        } catch { }
    }
    return $pending
}

# One backup per version, taken from the binary the running service uses - never from the
# freshly extracted download. Returns the backup path or $null.
function Backup-RunningSysmon {
    param($Installed, $Version)
    if (-not $Installed -or -not $Installed.FromService -or -not $Version) { return $null }
    if (-not (Test-SysmonRunning)) { return $null }
    $runningVersion = Get-RunningSysmonVersion
    if ($runningVersion -and $runningVersion -ne $Version) {
        Write-Host "[!] Running Sysmon is $runningVersion but its binary says $Version - no backup taken" -ForegroundColor Yellow
        return $null
    }
    try {
        $dir = Join-Path $backupDir "$Version"
        $dest = Join-Path $dir (Split-Path $Installed.Exe -Leaf)
        if ((Test-Path $dest) -and ((Get-BinaryVersion -Path $dest) -eq $Version)) { return $dest }
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Copy-Item -Path $Installed.Exe -Destination $dest -Force
        if ((Get-BinaryVersion -Path $dest) -eq $Version) {
            Write-Host "[*] Backed up Sysmon $Version to $dest" -ForegroundColor Gray
            return $dest
        }
    } catch {
        Write-Host "[!] Could not back up the installed Sysmon: $_" -ForegroundColor Yellow
    }
    return $null
}

# A one-shot task that puts the backed-up Sysmon back at the next boot, in case this
# script is interrupted or the old Sysmon is still pending deletion.
function Register-SysmonRecovery {
    param([string]$Exe)
    try {
        $command = "if (-not (Get-Service -Name Sysmon64a,Sysmon64 -ErrorAction SilentlyContinue | Where-Object { `$_.Status -eq 'Running' })) { & '$Exe' -accepteula -i '$configPath' }; " +
            "if (Get-Service -Name Sysmon64a,Sysmon64 -ErrorAction SilentlyContinue | Where-Object { `$_.Status -eq 'Running' }) { Unregister-ScheduledTask -TaskName 'TDC-SysmonRecover' -Confirm:`$false }"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "TDC-SysmonRecover" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        Write-Host "[*] Recovery task TDC-SysmonRecover registered (reinstalls the backup at boot)" -ForegroundColor Gray
    } catch {
        Write-Host "[!] Could not register the recovery task: $_" -ForegroundColor Yellow
    }
}

function Unregister-SysmonRecovery {
    Unregister-ScheduledTask -TaskName "TDC-SysmonRecover" -Confirm:$false -ErrorAction SilentlyContinue
}

# After -u force the services and the event channel go away asynchronously; installing
# too early fails with "driver already registered" or "event manifest installation failed".
function Wait-SysmonGone {
    param([int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $left = @()
        foreach ($name in @("Sysmon64a", "Sysmon64", "SysmonDrv")) {
            if (Test-ServiceExists $name) { $left += $name }
        }
        wevtutil gl Microsoft-Windows-Sysmon/Operational 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $left += "channel" }
        if ($left.Count -eq 0) { return $true }
        if ((Get-Date) -ge $deadline) {
            Write-Host "[!] Still registered after ${TimeoutSeconds}s: $($left -join ', ')" -ForegroundColor Yellow
            return $false
        }
        Start-Sleep -Seconds 2
    }
}

# -u force, then wait; $true when everything is gone.
function Uninstall-SysmonBinary {
    param([string]$Exe)
    & $Exe -accepteula -u force 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    return (Wait-SysmonGone -TimeoutSeconds 60)
}

# Sysmon runs and, when a version is expected, it is that version.
function Test-SysmonInstalledOk {
    param($ExpectedVersion)
    if (-not (Test-SysmonRunning)) { return $false }
    if (-not $ExpectedVersion) { return $true }
    $runningVersion = Get-RunningSysmonVersion
    if (-not $runningVersion) {
        Write-Host "[!] Could not read the running Sysmon version" -ForegroundColor Yellow
        return $true
    }
    if ($runningVersion -ne $ExpectedVersion) {
        Write-Host "[!] Sysmon $runningVersion runs, expected $ExpectedVersion" -ForegroundColor Yellow
        return $false
    }
    return $true
}

# -i with up to 3 attempts; with -Force a partial state is removed with -u force between tries.
function Install-SysmonService {
    param([string]$Exe, $ExpectedVersion = $null)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        Write-Host "[*] Installing Sysmon service ($([System.IO.Path]::GetFileName($Exe)), attempt $attempt of 3)..." -ForegroundColor Yellow
        & $Exe -accepteula -i $configPath 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        Start-Sleep -Seconds 3
        if (-not (Test-SysmonRunning)) {
            foreach ($name in @("Sysmon64a", "Sysmon64")) {
                if (Test-ServiceExists $name) { Start-Service -Name $name -ErrorAction SilentlyContinue }
            }
            Start-Sleep -Seconds 2
        }
        if (Test-SysmonInstalledOk -ExpectedVersion $ExpectedVersion) { return $true }
        if ($attempt -lt 3) {
            Write-Host "[!] Sysmon is not running as expected - waiting 10 s before the next attempt" -ForegroundColor Yellow
            Start-Sleep -Seconds 10
            if ($Force) {
                [void](Uninstall-SysmonBinary -Exe $Exe)
            }
        }
    }
    return $false
}

# Check if already installed and running
$sysmonSvc = Get-Service -Name $sysmonServiceName -ErrorAction SilentlyContinue
if (-not $sysmonSvc) {
    # Also check alternate service name (ARM64 may register as Sysmon64)
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
}
if ($sysmonSvc -and $sysmonSvc.Status -eq "Running" -and -not $Force) {
    Write-Host "[+] Sysmon already installed and running" -ForegroundColor Green
    Write-Host "[*] Updating configuration..." -ForegroundColor Yellow
    # Re-download config to get latest updates (to a temp file first, so a
    # failed download never leaves a half-written config behind)
    $configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    $configTmp = "$env:TEMP\sysmonconfig.xml.download"
    try {
        $response = Invoke-WebRequest -Uri $configUrl -OutFile $configTmp -UseBasicParsing -PassThru
        $configEtag = Get-ETag $response
        Move-Item -Path $configTmp -Destination $configPath -Force -ErrorAction Stop
        Set-PipeEventExclude -Path $configPath
        Set-NetworkConnectIncludes -Path $configPath
        $installedNow = Get-InstalledSysmon
        $configExe = if ($installedNow -and $installedNow.Exe) { $installedNow.Exe } else { $sysmonExe }
        & $configExe -c $configPath 2>$null
        $configExit = $LASTEXITCODE
        Set-SysmonLogSize
        if ($configExit -ne 0) {
            # The marker keeps the old ETag, so the next check still offers the update
            Write-Host "[!] sysmon -c failed (exit $configExit) - config not applied" -ForegroundColor Yellow
        } else {
            Save-SourceEtag -Key "config_etag" -Value $configEtag
            Write-Host "[+] Sysmon config updated" -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] Config update failed: $_" -ForegroundColor Yellow
    }
    Remove-Item $configTmp -Force -ErrorAction SilentlyContinue
    exit 0
}

# Create directory
New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null

# Download Sysmon
Write-Host "[*] Downloading Sysmon..." -ForegroundColor Yellow
$sysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZipPath = "$env:TEMP\Sysmon.zip"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$binaryEtag = ""
try {
    $response = Invoke-WebRequest -Uri $sysmonZipUrl -OutFile $sysmonZipPath -UseBasicParsing -PassThru
    $binaryEtag = Get-ETag $response
    Write-Host "[+] Sysmon downloaded" -ForegroundColor Green
} catch {
    if ($Force) {
        # The old install is still in place; do not report it as a fresh one.
        Write-Host "[!] Download failed: $($_.Exception.Message) - Sysmon left as it was" -ForegroundColor Red
        exit 1
    }
    Write-Host "[!] Download failed, trying Chocolatey fallback..." -ForegroundColor Yellow
    choco install sysmon -y --no-progress 2>$null
    if (Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue) {
        Write-Host "[+] Sysmon installed via Chocolatey" -ForegroundColor Green
        exit 0
    }
    Write-Host "[!] Sysmon installation failed" -ForegroundColor Red
    exit 1
}

# What is installed now: the binary the service runs (ImagePath), else the tools dir one
$installed = Get-InstalledSysmon
$installedServiceName = $null
$installedExe = $null
$installedFromService = $false
if ($installed) {
    $installedServiceName = $installed.Name
    $installedExe = $installed.Exe
    $installedFromService = $installed.FromService
}
$installedVersion = Get-BinaryVersion -Path $installedExe
if (-not $installedVersion) {
    $installedVersion = Get-BinaryVersion -Path $sysmonExe
}

# Back up the running binary (one copy per version) before the extraction overwrites the tools dir
$backupDir = "$sysmonDir\backup"
$backupExe = Backup-RunningSysmon -Installed $installed -Version $installedVersion

# Extract
Write-Host "[*] Extracting Sysmon..." -ForegroundColor Yellow
Expand-Archive -Path $sysmonZipPath -DestinationPath $sysmonDir -Force
Remove-Item $sysmonZipPath -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $sysmonExe)) {
    Write-Host "[!] $([System.IO.Path]::GetFileName($sysmonExe)) not found after extraction" -ForegroundColor Red
    # Check for alternate names
    $candidates = @("$sysmonDir\Sysmon64a.exe", "$sysmonDir\Sysmon64.exe", "$sysmonDir\sysmon64.exe", "$sysmonDir\sysmon64a.exe")
    $found = $false
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            $sysmonExe = $candidate
            $found = $true
            Write-Host "[*] Using $candidate" -ForegroundColor Yellow
            break
        }
    }
    if (-not $found) {
        Write-Host "[!] No Sysmon binary found. Contents:" -ForegroundColor Red
        Get-ChildItem $sysmonDir | ForEach-Object { Write-Host "    $_" }
        exit 1
    }
}

# Download SwiftOnSecurity sysmon config (comprehensive, well-tuned)
Write-Host "[*] Downloading SwiftOnSecurity sysmon-config..." -ForegroundColor Yellow
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$configEtag = ""
$configTmp = "$env:TEMP\sysmonconfig.xml.download"
try {
    $response = Invoke-WebRequest -Uri $configUrl -OutFile $configTmp -UseBasicParsing -PassThru
    $configEtag = Get-ETag $response
    Move-Item -Path $configTmp -Destination $configPath -Force -ErrorAction Stop
    Write-Host "[+] Sysmon config downloaded" -ForegroundColor Green
} catch {
    Remove-Item $configTmp -Force -ErrorAction SilentlyContinue
    if ($Force -and (Test-Path $configPath)) {
        # The config in place is the one the admin has; a minimal one would be a downgrade
        Write-Host "[!] Config download failed - keeping the existing $configPath" -ForegroundColor Yellow
    } else {
    Write-Host "[!] Config download failed, using minimal config" -ForegroundColor Yellow
    # Minimal config that logs everything important
    $minimalConfig = @"
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <FileCreateTime onmatch="exclude" />
    <NetworkConnect onmatch="exclude" />
    <ProcessTerminate onmatch="exclude" />
    <DriverLoad onmatch="exclude" />
    <ImageLoad onmatch="exclude" />
    <CreateRemoteThread onmatch="exclude" />
    <RawAccessRead onmatch="exclude" />
    <ProcessAccess onmatch="exclude" />
    <FileCreate onmatch="exclude" />
    <RegistryEvent onmatch="exclude" />
    <FileCreateStreamHash onmatch="exclude" />
    <PipeEvent onmatch="exclude" />
    <WmiEvent onmatch="exclude" />
    <DnsQuery onmatch="exclude" />
    <FileDelete onmatch="exclude" />
    <ClipboardChange onmatch="exclude" />
    <ProcessTampering onmatch="exclude" />
    <FileBlockExecutable onmatch="exclude" />
    <FileBlockShredding onmatch="exclude" />
  </EventFiltering>
</Sysmon>
"@
    Set-Content -Path $configPath -Value $minimalConfig
    }
}
Set-PipeEventExclude -Path $configPath
Set-NetworkConnectIncludes -Path $configPath

# Same or older version already running: keep it, only apply the new config
$downloadedVersion = Get-BinaryVersion -Path $sysmonExe
if ($Force -and (Test-SysmonRunning) -and $installedExe -and $installedVersion -and $downloadedVersion -and
    ($downloadedVersion -le $installedVersion)) {
    Write-Host "[*] Installed Sysmon $installedVersion, downloaded $downloadedVersion - no reinstall needed" -ForegroundColor Yellow
    & $installedExe -accepteula -c $configPath 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    $configExit = $LASTEXITCODE
    Set-SysmonLogSize
    if ($configExit -ne 0) {
        Write-Host "[!] sysmon -c failed (exit $configExit) - config not applied; Sysmon $installedVersion keeps running" -ForegroundColor Red
        exit 1
    }
    if ($binaryEtag -and $installedFromService) { Save-SourceEtag -Key "binary_etag" -Value $binaryEtag }
    if ($configEtag) { Save-SourceEtag -Key "config_etag" -Value $configEtag }
    Write-Host "[+] Sysmon $installedVersion is current; configuration updated" -ForegroundColor Green
    exit 0
}

# Reinstall: the old service and driver have to go before the new ones.
if ($Force) {
    # A service or driver waiting for deletion blocks the install until a reboot; the old Sysmon still runs here
    $pending = @(Get-PendingDeletion)
    if ($pending.Count -gt 0) {
        Write-Host "[!] reboot required: $($pending -join ', ') is pending deletion. Sysmon was left as it was." -ForegroundColor Red
        exit 1
    }
    if ((Test-SysmonRunning) -and -not $backupExe) {
        Write-Host "[!] The running Sysmon could not be backed up - not reinstalling, it keeps running" -ForegroundColor Red
        exit 1
    }
    if ($backupExe) { Register-SysmonRecovery -Exe $backupExe }
}
if ($Force -and $installedServiceName) {
    # Prefer the version-matched backup copy: the service image in C:\Windows may defer its own deletion
    $uninstallExe = $null
    if ($backupExe) { $uninstallExe = Join-Path (Join-Path $backupDir "$installedVersion") "$installedServiceName.exe" }
    if (-not $uninstallExe -or -not (Test-Path $uninstallExe)) { $uninstallExe = $installedExe }
    if (-not $uninstallExe -or -not (Test-Path $uninstallExe)) { $uninstallExe = $sysmonExe }
    Write-Host "[*] Uninstalling the installed Sysmon (-u force, $uninstallExe)..." -ForegroundColor Yellow
    $gone = Uninstall-SysmonBinary -Exe $uninstallExe
    if (-not $gone) {
        $pending = @(Get-PendingDeletion)
        if ($pending.Count -gt 0) {
            Write-Host "[!] reboot required: $($pending -join ', ') is pending deletion. The recovery task TDC-SysmonRecover reinstalls Sysmon at boot." -ForegroundColor Red
            exit 1
        }
    }
}

# Verify installation: install with retries, then check that the expected version runs
$sysmonRunning = Install-SysmonService -Exe $sysmonExe -ExpectedVersion $downloadedVersion
Set-SysmonLogSize

if ($sysmonRunning) {
    Write-Host "[+] Sysmon installed and running" -ForegroundColor Green
} else {
    Write-Host "[!] Sysmon service not running (or not the new version) - check logs" -ForegroundColor Red
}

if ($Force -and -not $sysmonRunning) {
    # Never leave the VM without Sysmon: put the previous version back
    $rollbackExe = $null
    if ($installedServiceName -and $installedVersion) {
        $rollbackExe = Join-Path (Join-Path $backupDir "$installedVersion") "$installedServiceName.exe"
    }
    if ($rollbackExe -and (Test-Path $rollbackExe)) {
        Write-Host "[*] Rolling back to the previous Sysmon ($rollbackExe)..." -ForegroundColor Yellow
        $gone = Uninstall-SysmonBinary -Exe $sysmonExe
        if (-not $gone -and @(Get-PendingDeletion).Count -gt 0) {
            Write-Host "[!] reboot required: the failed Sysmon is pending deletion. The recovery task TDC-SysmonRecover restores the previous version at boot." -ForegroundColor Red
            exit 1
        }
        if (Install-SysmonService -Exe $rollbackExe -ExpectedVersion $installedVersion) {
            Set-SysmonLogSize
            Unregister-SysmonRecovery
            Write-Host "[!] New Sysmon failed to install; restored the previous version" -ForegroundColor Red
        } else {
            Write-Host "[!] Rollback failed - Sysmon is NOT running. The recovery task TDC-SysmonRecover retries at boot, or by hand: $rollbackExe -accepteula -i $configPath" -ForegroundColor Red
        }
    } else {
        Write-Host "[!] Sysmon failed to install and there is no backed-up binary to roll back to" -ForegroundColor Red
    }
    exit 1
}
# The ETags are recorded only for an install that runs, binary_etag only for the downloaded version
if ($sysmonRunning) {
    Unregister-SysmonRecovery
    $runningVersion = Get-RunningSysmonVersion
    if ($binaryEtag -and $downloadedVersion -and $runningVersion -and ($runningVersion -eq $downloadedVersion)) {
        Save-SourceEtag -Key "binary_etag" -Value $binaryEtag
    }
    if ($configEtag) { Save-SourceEtag -Key "config_etag" -Value $configEtag }
}

# Add Sysmon to PATH
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$sysmonDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$sysmonDir", "Machine")
    $env:Path = "$sysmonDir;$env:Path"
}

# Add Defender exclusion for Sysmon directory
Add-MpPreference -ExclusionPath $sysmonDir -ErrorAction SilentlyContinue

Write-Host "`n[+] Sysmon installation complete!" -ForegroundColor Green
Write-Host "    Directory:  $sysmonDir" -ForegroundColor Gray
Write-Host "    Config:     $configPath" -ForegroundColor Gray
Write-Host "    Event Log:  Microsoft-Windows-Sysmon/Operational" -ForegroundColor Gray
Write-Host "    Service:    $sysmonServiceName" -ForegroundColor Gray
