# install-ntsleuth.ps1
# Installs NTSleuth - the syscall extractor behind the web UI's SYSCALLS tab.
#
# NTSleuth (https://github.com/xaitax/NTSleuth, BSD-3-Clause):
#   - Extracts every syscall of ntdll.dll and win32u.dll with its number, RVA,
#     parameters and stub bytes, as JSON
#   - Runs unchanged as a binary; the web UI measures live processes against
#     the JSON it wrote for this build ("baseline")
#   - Statically linked: no VC++ redistributable is needed
#
# The release (a date tag such as v2025.08.30-2e15c17) carries ntsleuth-arm64.exe,
# ntsleuth-x64.exe, ntsleuth-x86.exe and checksums.txt. The files keep their
# release names; there is no unsuffixed binary. An ARM64 VM gets two of them:
# ntdll.dll of an ARM64X system shows two views, the native ARM64 one and the
# x64/EC one that emulated x64 samples run against, and each has its own RVAs
# and stub bytes. The x64 binary extracts the second view under emulation. An
# x64 VM gets ntsleuth-x64.exe only.
#
# Every binary is verified against the SHA-256 in the release's checksums.txt
# before it reaches C:\tools\ntsleuth. A hash that does not match, or is
# missing, ends the script with exit code 1 and installs nothing: the binaries
# run as SYSTEM on a machine that also runs malware.
#
# Expected paths after install:
#   C:\tools\ntsleuth\ntsleuth-arm64.exe   (ARM64 only)
#   C:\tools\ntsleuth\ntsleuth-x64.exe
#   C:\tools\ntsleuth\baseline\ntsleuth-<build>-<view>.json
#       <build> is CurrentBuildNumber.UBR of the registry (e.g. 26220.5770),
#       <view> is arm64 or x64. The web UI looks for exactly these names.
#   C:\tools\ntsleuth\tdc-release.txt
#       first line the release tag, then one "<file> sha256:<hash>" line per binary
#
# Each view is then self-tested (extract, then --lookup NtCreateProcess has to
# print a syscall number). The marker is written when that worked, so the tool
# updates keep offering the update until it does. The baselines are stored after
# the marker and do not gate it.
#
# Exit codes: 1 for what must never leave a bad install behind (a failed
# download, a missing or mismatching checksum, a binary that cannot be copied,
# an unsupported architecture). Everything after the verified install, the
# self-test and the baselines, only warns and exits 0: NTSleuth is an addition
# to the chamber, so provisioning goes on and the SYSCALLS tab reports what is
# missing.
#
# On ARM64 the two baselines are compared: ntsleuth-x64.exe has to see the x64
# view of ntdll.dll, and if its extraction equals the ARM64 one the script says
# so loudly.
#
# Run as Administrator
#
# Parameters:
#   -Force            reinstall even if NTSleuth and its baselines exist (used by the tool updates)
#   -Version <tag>    release tag to install, e.g. v2025.08.30-2e15c17 (default: the latest
#                     release; the pinned tag below if GitHub cannot be reached)

param(
    [switch]$Force,
    [string]$Version = ""
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest
# The progress bar slows Invoke-WebRequest down badly.
$ProgressPreference = "SilentlyContinue"

Write-Host "=== Installing NTSleuth (syscall extraction) ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$InstallDir      = "C:\tools\ntsleuth"
$BaselineDir     = "$InstallDir\baseline"
$OutputJson      = "$InstallDir\output\syscalls.json"
$Repo            = "xaitax/NTSleuth"
$FallbackVersion = "v2025.08.30-2e15c17"  # used if the GitHub API is unreachable
$SymbolServer    = "msdl.microsoft.com"
$ExtractTimeout  = 300
$LookupTimeout   = 60
$Staging         = Join-Path ([IO.Path]::GetTempPath()) "tdc-ntsleuth"

# Ends the script, and leaves nothing of the download behind.
function Stop-Install([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Red
    Write-Host "    NTSleuth was not (re)installed; the SYSCALLS tab reports what is missing." -ForegroundColor Red
    Remove-Item $Staging -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

# OS architecture from the registry (children of emulated x64 processes see AMD64)
$osArch = $null
try {
    $osArch = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PROCESSOR_ARCHITECTURE -ErrorAction Stop).PROCESSOR_ARCHITECTURE
} catch { $osArch = $null }
if (-not $osArch) { $osArch = $env:PROCESSOR_ARCHITEW6432 }
if (-not $osArch) { $osArch = $env:PROCESSOR_ARCHITECTURE }
$isArm64 = ($osArch -eq "ARM64")

# One baseline per view of ntdll.dll; an x86 system has no view the web UI measures
if ($isArm64) {
    $Views = @("arm64", "x64")
} elseif ($osArch -eq "AMD64") {
    $Views = @("x64")
} else {
    Stop-Install "Unsupported architecture '$osArch': NTSleuth is installed for ARM64 and x64 systems"
}
$Assets = @($Views | ForEach-Object { "ntsleuth-$_.exe" })

# <build> of the baseline names: CurrentBuildNumber.UBR, e.g. 26220.5770
$build = $null
try {
    $cv = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
    $ubr = [int]$cv.UBR
    $number = [string]$cv.CurrentBuildNumber
    if ($number -match '^[0-9]+$') { $build = "$number.$ubr" }
} catch { $build = $null }
if (-not $build) {
    Write-Host "[!] The build of this system cannot be read from the registry (CurrentBuildNumber, UBR): no baseline can be named" -ForegroundColor Yellow
}

# A baseline is a file the web UI finds by name; the name has to be the one it looks for.
function Test-Baseline([string]$View) {
    if (-not $build) { return $false }
    $name = "ntsleuth-$build-$View.json"
    if ($name -notmatch '^ntsleuth-[0-9A-Za-z.]+-(arm64|x64)\.json$') { return $false }
    $file = Get-Item -Path "$BaselineDir\$name" -ErrorAction SilentlyContinue
    return [bool]($file -and $file.Length -gt 0)
}

# Short cut: the binaries, the baselines of this build and the marker are all there
$wantTag = if ($Version) { $Version } else { $null }
if ($wantTag -and $wantTag -notmatch '^v?[0-9][0-9A-Za-z._-]*$') {
    Stop-Install "Invalid -Version '$Version': expected a release tag such as $FallbackVersion"
}
if ($wantTag -and -not $wantTag.StartsWith("v")) { $wantTag = "v$wantTag" }

$markerTag = ""
try { $markerTag = ((Get-Content -Path "$InstallDir\tdc-release.txt" -ErrorAction Stop | Select-Object -First 1) -as [string]).Trim() } catch { }
$complete = [bool]$markerTag
foreach ($view in $Views) {
    if (-not (Test-Path "$InstallDir\ntsleuth-$view.exe") -or -not (Test-Baseline $view)) { $complete = $false }
}
if ($complete -and $wantTag -and ($markerTag -ne $wantTag)) { $complete = $false }
if ($complete -and -not $Force) {
    Write-Host "[+] NTSleuth $markerTag already installed at $InstallDir (baselines of build $build present)" -ForegroundColor Green
    return
}

New-Item -ItemType Directory -Path $InstallDir, $BaselineDir -Force | Out-Null

# Defender exclusion: a syscall extractor and its output trip heuristics.
# Set before anything is written, or the binaries may be quarantined on arrival.
if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
}

# --- Which release ---
$Tag = $wantTag
if (-not $Tag) {
    try {
        Write-Host "[*] Querying latest NTSleuth release..." -ForegroundColor Yellow
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ "User-Agent" = "tdc-installer" } -TimeoutSec 30 -ErrorAction Stop
        $names = @($release.assets | ForEach-Object { $_.name })
        foreach ($need in ($Assets + "checksums.txt")) {
            if ($names -notcontains $need) { Stop-Install "Release $($release.tag_name) has no asset $need" }
        }
        if ([string]$release.tag_name -notmatch '^v?[0-9][0-9A-Za-z._-]*$') {
            Stop-Install "Release tag '$($release.tag_name)' is not a tag this script can use"
        }
        $Tag = [string]$release.tag_name
        Write-Host "    Latest: $Tag" -ForegroundColor Gray
    } catch {
        Write-Host "[!] GitHub API query failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
if (-not $Tag) {
    $Tag = $FallbackVersion
    Write-Host "[*] Falling back to pinned release $FallbackVersion" -ForegroundColor Yellow
}
$baseUrl = "https://github.com/$Repo/releases/download/$Tag"

# --- Download ---
if (Test-Path $Staging) { Remove-Item $Staging -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $Staging -Force | Out-Null
foreach ($file in (@("checksums.txt") + $Assets)) {
    try {
        Write-Host "[*] Downloading $baseUrl/$file" -ForegroundColor Gray
        Invoke-WebRequest -Uri "$baseUrl/$file" -OutFile "$Staging\$file" -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    } catch {
        Stop-Install "Download of $file failed: $($_.Exception.Message)"
    }
}

# --- Verify every binary against checksums.txt ---
# The file is sha256sum text: "<64 hex digits>  <file name>", one line per asset.
$sums = @{}
foreach ($line in (Get-Content -Path "$Staging\checksums.txt" -ErrorAction SilentlyContinue)) {
    if ($line -match '^\s*([0-9A-Fa-f]{64})\s+\*?(\S+)\s*$') { $sums[$Matches[2].ToLower()] = $Matches[1].ToLower() }
}
$hashes = @{}
foreach ($asset in $Assets) {
    if (-not $sums.ContainsKey($asset.ToLower())) { Stop-Install "checksums.txt of $Tag has no SHA-256 for $asset" }
    $actual = ""
    try { $actual = (Get-FileHash -Path "$Staging\$asset" -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
    if ($actual -ne $sums[$asset.ToLower()]) {
        Write-Host "    expected $($sums[$asset.ToLower()])" -ForegroundColor Red
        Write-Host "    got      $actual" -ForegroundColor Red
        Stop-Install "SHA-256 mismatch for ${asset}: the download is deleted"
    }
    $hashes[$asset] = $actual
    Write-Host "[+] SHA-256 verified: $asset $actual" -ForegroundColor Green
}

# --- Install ---
# The marker names a release that is about to stop being what is installed
Remove-Item "$InstallDir\tdc-release.txt" -Force -ErrorAction SilentlyContinue
# -ErrorAction Stop: a locked binary (an extraction is running) must not count as installed
try {
    foreach ($asset in $Assets) {
        Copy-Item -Path "$Staging\$asset" -Destination $InstallDir -Force -ErrorAction Stop
    }
} catch {
    Stop-Install "Copying to $InstallDir failed: $($_.Exception.Message)"
}
Remove-Item $Staging -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[+] NTSleuth $Tag installed to $InstallDir" -ForegroundColor Green

# --- Self-test, marker, baselines ---
function Test-SymbolServer {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($SymbolServer, 443, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(3000)) { return $false }
        $client.EndConnect($pending)
        return $true
    } catch { return $false } finally { $client.Close() }
}

# Runs NTSleuth from the install dir, as the web UI does, and returns its exit code and output.
function Invoke-NtSleuth([string]$Exe, [string[]]$Arguments, [int]$TimeoutSec) {
    $out = "$env:TEMP\ntsleuth-out.txt"
    $err = "$env:TEMP\ntsleuth-err.txt"
    Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
    $code = -1
    try {
        $proc = Start-Process -FilePath $Exe -ArgumentList $Arguments -WorkingDirectory $InstallDir -NoNewWindow `
            -PassThru -RedirectStandardOutput $out -RedirectStandardError $err -ErrorAction Stop
        if ($proc.WaitForExit($TimeoutSec * 1000)) {
            $code = $proc.ExitCode
        } else {
            $proc.Kill()
            Write-Host "[!] $([IO.Path]::GetFileName($Exe)) timed out after ${TimeoutSec}s" -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] $([IO.Path]::GetFileName($Exe)) did not run: $($_.Exception.Message)" -ForegroundColor Red
    }
    $text = ""
    foreach ($f in @($out, $err)) {
        if (Test-Path $f) { $text += (Get-Content -Path $f -Raw -ErrorAction SilentlyContinue) + "`n" }
    }
    Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Code = $code; Text = [string]$text }
}

# Without the symbol server NTSleuth would wait on downloads that never come.
# The measurement does not need the symbols: numbers, RVAs and stub bytes come
# from the disassembly; only the parameter table is incomplete.
$symbols = Test-SymbolServer
if ($symbols) {
    Write-Host "[*] Symbol server reachable: extracting with parameters" -ForegroundColor Gray
} else {
    Write-Host "[!] Symbol server $SymbolServer not reachable: extracting with --no-symbols (parameter table incomplete)" -ForegroundColor Yellow
}

# Self-test: each view has to extract and to look NtCreateProcess up. The extractions are kept in memory;
# the baselines are stored from them afterwards, once the marker is written.
$selfTestOk = $true
$extractions = @{}
foreach ($view in $Views) {
    $exe = "$InstallDir\ntsleuth-$view.exe"
    Write-Host "[*] Self-testing ntsleuth-$view.exe..." -ForegroundColor Yellow
    # a file left by an earlier run must not pass for this one
    Remove-Item $OutputJson -Force -ErrorAction SilentlyContinue

    $arguments = @("--auto-params", "--format", "json")
    if (-not $symbols) { $arguments += "--no-symbols" }
    $run = Invoke-NtSleuth $exe $arguments $ExtractTimeout
    if (($run.Code -ne 0) -or -not (Test-Path $OutputJson)) {
        $tail = ($run.Text.Trim() -split "`r?`n" | Select-Object -Last 1)
        Write-Host "[!] ntsleuth-$view.exe exited with $($run.Code) and wrote no $OutputJson ($tail)" -ForegroundColor Red
        $selfTestOk = $false
        continue
    }

    # --lookup exits 0 even when the name is missing or the JSON unreadable: the number has to be in the output.
    # The labels are coloured with escape codes, which are taken out first.
    $lookup = Invoke-NtSleuth $exe @("--lookup", "NtCreateProcess") $LookupTimeout
    $plain = $lookup.Text -replace '\x1b\[[0-9;]*m', ''
    if ($plain -match '\[Number\]\s+0x[0-9A-Fa-f]+\s+\((\d+)\)') {
        Write-Host "[+] NtCreateProcess is syscall $($Matches[1]) in the $view view" -ForegroundColor Green
    } else {
        Write-Host "[!] ntsleuth-$view.exe --lookup NtCreateProcess gave no syscall number:" -ForegroundColor Red
        Write-Host "    $($plain.Trim())" -ForegroundColor DarkGray
        $selfTestOk = $false
        continue
    }
    try {
        $json = [IO.File]::ReadAllText($OutputJson, (New-Object System.Text.UTF8Encoding($false)))
        if ($json.TrimStart()[0] -ne '{') { throw "the JSON does not start with an object" }
        $extractions[$view] = $json
    } catch {
        Write-Host "[!] The $view extraction cannot be read: $($_.Exception.Message)" -ForegroundColor Red
        $selfTestOk = $false
    }
}
Remove-Item "$InstallDir\output" -Recurse -Force -ErrorAction SilentlyContinue

# --- Marker: the tag first, as the tool updates read the first line only ---
# Written when the binaries are verified, installed and work. The baselines below do not gate it: a baseline
# that fails leaves a good install, and the update must not stay on offer for that.
if ($selfTestOk) {
    $markerLines = @($Tag)
    foreach ($asset in $Assets) { $markerLines += "$asset sha256:$($hashes[$asset])" }
    Set-Content -Path "$InstallDir\tdc-release.txt" -Value $markerLines -Encoding ASCII
} else {
    Write-Host "[!] NTSleuth is installed, but the self-test failed (see above): no marker is written, so the update stays on offer" -ForegroundColor Red
}

# --- Baselines ---
# From here on nothing ends the script with an error: the chamber is provisioned without them, the tab says
# "no baseline", and the web UI extracts one on demand.
# A fingerprint of what tells the views apart: the RVA and stub bytes of every entry. The extraction's
# metadata (times, order of keys) is no part of it.
function Get-ViewFingerprint([string]$Json) {
    $parts = @([regex]::Matches($Json, '"(?:rva|stub_bytes)"\s*:\s*(?:\d+|"[0-9A-Fa-f]*")') | ForEach-Object { $_.Value })
    if ($parts.Count -eq 0) { return "" }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($parts -join "`n")))) -replace "-", "")
}

$stored = @()
foreach ($view in $Views) {
    if (-not $extractions.ContainsKey($view)) {
        Write-Host "[!] No baseline for the $view view: its extraction did not work" -ForegroundColor Yellow
        continue
    }
    if (-not $build) { continue }
    # Written beside its final name and moved over it, so the web UI never reads half a file.
    $target = "$BaselineDir\ntsleuth-$build-$view.json"
    try {
        $json = $extractions[$view]
        # The web UI reads "symbols": false as "the parameter table is incomplete"
        if (-not $symbols) { $json = '{"symbols":false,' + $json.TrimStart().Substring(1) }
        [IO.File]::WriteAllText("$target.tmp", $json, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -Path "$target.tmp" -Destination $target -Force -ErrorAction Stop
    } catch {
        Remove-Item "$target.tmp" -Force -ErrorAction SilentlyContinue
        Write-Host "[!] The $view baseline could not be stored: $($_.Exception.Message)" -ForegroundColor Yellow
        continue
    }
    if (Test-Baseline $view) {
        Write-Host "[+] Baseline: $target" -ForegroundColor Green
        $stored += $view
    } else {
        Write-Host "[!] $target is missing or empty after the extraction" -ForegroundColor Yellow
    }
}

# On ARM64 the x64 binary has to see the other view of ntdll.dll. If both extractions are the same, the x64
# baseline is the ARM64 one under another name, and every measurement of an emulated x64 sample would be
# made against the wrong reference.
if ($isArm64 -and $extractions.ContainsKey("arm64") -and $extractions.ContainsKey("x64")) {
    $armPrint = Get-ViewFingerprint $extractions["arm64"]
    $x64Print = Get-ViewFingerprint $extractions["x64"]
    if (-not $armPrint -or -not $x64Print) {
        Write-Host "[!] The arm64 and x64 extractions could not be compared (no RVA or stub bytes found)" -ForegroundColor Yellow
    } elseif ($armPrint -eq $x64Print) {
        Write-Host "[!] BASELINES IDENTICAL: ntsleuth-x64.exe reports the same RVAs and stub bytes as ntsleuth-arm64.exe." -ForegroundColor Red
        Write-Host "    It did not see the x64 view of ntdll.dll. Do not trust the x64 baseline: syscall measurements" -ForegroundColor Red
        Write-Host "    of emulated x64 samples would run against the ARM64 stubs." -ForegroundColor Red
    } else {
        Write-Host "[+] The arm64 and x64 views differ, as they must" -ForegroundColor Green
    }
}

Write-Host "`n[+] NTSleuth installation complete!" -ForegroundColor Green
Write-Host "    Release:    $Tag" -ForegroundColor Gray
Write-Host "    Executable: $($Assets -join ', ') in $InstallDir" -ForegroundColor Gray
if ($stored.Count -gt 0) {
    Write-Host "    Baselines:  $BaselineDir (build $build, $($stored -join ', '))" -ForegroundColor Gray
} else {
    Write-Host "    Baselines:  none stored; the SYSCALLS tab says so and extracts one on demand" -ForegroundColor Yellow
}
if ($isArm64) {
    Write-Host "    NOTE: ntsleuth-x64.exe runs under x64 emulation; it extracts the view emulated x64 samples run against." -ForegroundColor Gray
}
exit 0
