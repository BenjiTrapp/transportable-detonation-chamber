# build-binary-graph.ps1
# Builds the import graph cache behind the web UI's binary graph: the import and export tables of every PE in
# C:\Windows\System32, with every forwarder chain followed (through the api-set map) to the module that defines it.
#
# Nothing is downloaded and nothing is queried online: pefile reads the files of this VM, so the graph is the one of
# this build and this architecture. WinGraph is only ever linked to, never used.
#
# The cache is built by the web UI's own Python (webui\binary_graph.py); this script finds that interpreter, calls the
# module's command line and reports its numbers.
#
# Expected path after the build:
#   C:\tools\ntsleuth\baseline\binary-graph-<build>-<arch>.json
#       <build> is CurrentBuildNumber.UBR of the registry (e.g. 26220.5770), <arch> is arm64 or x64: the system's,
#       read from the registry, not a process's view of it. It sits beside the syscall baselines and is named
#       so that the two are never mistaken for each other. The web UI refuses a cache of any other stamp.
#
# Exit code: always 0. A graph that could not be built is a state the tab reports ("no graph") and builds on demand;
# a provisioning that stops here is not one. Every failure is a yellow warning with its reason.
#
# Run as Administrator, after install-ntsleuth.ps1 (the baseline directory) and install-webui.ps1 (the interpreter and
# the module)
#
# Parameters:
#   -Force   build again even if the cache of this build and architecture exists (used by the tool updates)

param(
    [switch]$Force
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Building the binary graph (System32 imports and forwarders) ===" -ForegroundColor Cyan

$BaselineDir  = "C:\tools\ntsleuth\baseline"
$WebUiDir     = "C:\DetonationChamberUI"
$Python       = "$WebUiDir\venv\Scripts\python.exe"
$Module       = "$WebUiDir\binary_graph.py"
$BuildTimeout = 1800

# Ends the script. A missing graph is reported, never an error: see the exit code above.
function Stop-Build([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
    Write-Host "    No graph was built; the binary graph tab reports that, and the web UI can build one on demand." -ForegroundColor Yellow
    exit 0
}

# OS architecture from the registry (children of emulated x64 processes see AMD64)
$osArch = $null
try {
    $osArch = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PROCESSOR_ARCHITECTURE -ErrorAction Stop).PROCESSOR_ARCHITECTURE
} catch { $osArch = $null }
if (-not $osArch) { $osArch = $env:PROCESSOR_ARCHITEW6432 }
if (-not $osArch) { $osArch = $env:PROCESSOR_ARCHITECTURE }
$arch = $null
if ($osArch -eq "ARM64") { $arch = "arm64" }
elseif ($osArch -eq "AMD64") { $arch = "x64" }
if (-not $arch) { Stop-Build "Unsupported architecture '$osArch': the graph is built for ARM64 and x64 systems" }

# <build> of the cache name: CurrentBuildNumber.UBR, the form of the syscall baselines
$build = $null
try {
    $cv = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
    $ubr = [int]$cv.UBR
    $number = [string]$cv.CurrentBuildNumber
    if ($number -match '^[0-9]+$') { $build = "$number.$ubr" }
} catch { $build = $null }
if (-not $build) { Stop-Build "The build of this system cannot be read from the registry (CurrentBuildNumber, UBR): no cache can be named" }

$cacheName = "binary-graph-$build-$arch.json"
if ($cacheName -notmatch '^binary-graph-[0-9A-Za-z.]+-(arm64|x64)\.json$') { Stop-Build "'$cacheName' is not a name the web UI looks for" }
$cachePath = "$BaselineDir\$cacheName"

# Short cut: the cache of this build and architecture is there
$existing = Get-Item -Path $cachePath -ErrorAction SilentlyContinue
if ($existing -and $existing.Length -gt 0 -and -not $Force) {
    Write-Host "[+] Binary graph of build $build ($arch) already present at $cachePath" -ForegroundColor Green
    exit 0
}

if (-not (Test-Path $Python)) { Stop-Build "The web UI's Python ($Python) is not there: install-webui.ps1 has not run" }
if (-not (Test-Path $Module)) { Stop-Build "$Module is not there: this web UI does not build a binary graph" }

New-Item -ItemType Directory -Path $BaselineDir -Force -ErrorAction SilentlyContinue | Out-Null
if (-not (Test-Path $BaselineDir)) { Stop-Build "$BaselineDir cannot be created" }

# --- Build ---
Write-Host "[*] Reading C:\Windows\System32 for build $build ($arch); this takes a few minutes..." -ForegroundColor Yellow
$out = "$env:TEMP\binary-graph-out.txt"
$err = "$env:TEMP\binary-graph-err.txt"
Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
$code = -1
try {
    $arguments = @("`"$Module`"", "--out", "`"$BaselineDir`"", "--build", $build, "--arch", $arch)
    $proc = Start-Process -FilePath $Python -ArgumentList $arguments -WorkingDirectory $WebUiDir -NoNewWindow `
        -PassThru -RedirectStandardOutput $out -RedirectStandardError $err -ErrorAction Stop
    # Windows PowerShell 5.1 reads ExitCode as $null after WaitForExit(ms) unless the process handle has been
    # taken first, and a $null code would report a graph that was built as a failure
    $null = $proc.Handle
    if ($proc.WaitForExit($BuildTimeout * 1000)) {
        $code = $proc.ExitCode
    } else {
        $proc.Kill()
        Write-Host "[!] The build timed out after ${BuildTimeout}s" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] The build did not run: $($_.Exception.Message)" -ForegroundColor Yellow
}

$counts = @{}
if (Test-Path $out) {
    foreach ($line in (Get-Content -Path $out -ErrorAction SilentlyContinue)) {
        if ($line -match '^([a-z_]+): (.*)$') { $counts[$Matches[1]] = $Matches[2] }
    }
}
$problem = ""
if (Test-Path $err) { $problem = ((Get-Content -Path $err -ErrorAction SilentlyContinue | Select-Object -Last 1) -as [string]) }
Remove-Item $out, $err -Force -ErrorAction SilentlyContinue

$built = Get-Item -Path $cachePath -ErrorAction SilentlyContinue
if ($code -ne 0 -or -not $built -or $built.Length -eq 0) {
    Write-Host "[!] The build ended with exit code $code and no usable $cacheName ($problem)" -ForegroundColor Yellow
    Stop-Build "The binary graph of build $build could not be built"
}

Write-Host "[+] Binary graph: $cachePath" -ForegroundColor Green
foreach ($key in @("binaries", "skipped", "api_sets", "resolved", "modules")) {
    if ($counts.ContainsKey($key)) { Write-Host "    ${key}: $($counts[$key])" -ForegroundColor Gray }
}
Write-Host "    Size: $([math]::Round($built.Length / 1MB, 1)) MB" -ForegroundColor Gray
if ($counts.ContainsKey("api_sets") -and $counts["api_sets"] -eq "0") {
    Write-Host "[!] The api-set map could not be read: forwarders over api-ms-win-* names are left unresolved" -ForegroundColor Yellow
}
if ($counts.ContainsKey("skipped") -and $counts["skipped"] -ne "0") {
    Write-Host "    $($counts['skipped']) files were skipped as unreadable; the tab says which" -ForegroundColor Gray
}
exit 0
