# install-aether.ps1
# Installs Aether - a live-process memory forensics and injection-detection scanner
#
# Source: https://github.com/0xsp-SRD/aether  (GNU GPL v3)
# Requires: Zig 0.16 (installed here if missing)
#
# Aether complements the existing memory tooling (PE-Sieve / Moneta /
# HollowsHunter via LitterBox) with three checks nothing else in the chamber
# performs:
#   - L8 TSAV: compares Win32StartAddress against the live RIP of suspended
#     threads, catching EarlyBird/APC start-address spoofing
#   - L9/L10: heap API-table detection, flagging runtime API resolution
#   - L5: page-level memory-vs-disk diff at matching RVAs
# On top of that it ships 380 in-memory signatures (ASCII + UTF-16LE) with
# MITRE mapping, and reports findings through a corroboration model that only
# promotes a hit when an independent signal agrees on the same allocation base.
#
# Expected paths:
#   C:\tools\Aether\Aether.exe
#   C:\tools\Aether\rules\*.json
#   C:\tools\zig\zig.exe          (build toolchain, kept for rebuilds)
#
# Note on ARM64 hosts: Aether is an x86/x64 tool - its thread-context probe
# uses the fixed AMD64 CONTEXT layout (RIP at offset 0xF8) and its hook
# prologues are x86/x64 opcodes. The x64 binary is installed deliberately and
# runs under Windows' x64 emulation, which is the right fit because detonated
# samples are x64 too. Structural, heap and signature checks work regardless;
# the TSAV RIP probe is only meaningful against x64 target processes.
#
# Run as Administrator
#
# Parameters (all optional; defaults match the provisioning layout):
#   -ToolRoot <dir>   install location (default C:\tools\Aether)
#   -NoPrebuilt       ignore C:\vagrant\prebuilt and always build in the VM
#                     (used to verify the in-VM Zig build path)

param(
    [string]$ToolRoot = "C:\tools\Aether",
    [switch]$NoPrebuilt
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Aether ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$SourceDir = "C:\tools\Aether-src"
$RepoUrl   = "https://github.com/0xsp-SRD/aether"
$ExePath   = "$ToolRoot\Aether.exe"

# Zig 0.16 is what Aether's build.zig targets; newer/older majors break it.
$ZigVersion = "0.16.0"
$ZigRoot    = "C:\tools\zig"

# A host-side build can be dropped here beforehand to skip the VM build
# entirely (see scripts/build-aether.sh). Checked before the "already
# installed" exit, so pushing a newer prebuilt actually updates the VM.
$prebuilt = "C:\vagrant\prebuilt\Aether.exe"
if ((-not $NoPrebuilt) -and (Test-Path $prebuilt)) {
    Write-Host "[*] Using prebuilt Aether.exe from $prebuilt" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path "$ToolRoot\rules" -Force | Out-Null
    Copy-Item $prebuilt $ExePath -Force
    if (Test-Path "C:\vagrant\prebuilt\rules") {
        # Copy the contents: copying the folder into an existing rules\
        # created rules\rules\ and left the old rules in use.
        Copy-Item "C:\vagrant\prebuilt\rules\*" "$ToolRoot\rules\" -Recurse -Force
    }
    Write-Host "[+] Aether installed at $ExePath" -ForegroundColor Green
    exit 0
}

if (Test-Path $ExePath) {
    Write-Host "[+] Aether already installed at $ExePath" -ForegroundColor Green
    exit 0
}

New-Item -ItemType Directory -Path $ToolRoot -Force | Out-Null

# --- Ensure Zig 0.16 ---
$zigExe = "$ZigRoot\zig.exe"
$zigOk = $false
if (Test-Path $zigExe) {
    try {
        $installed = (& $zigExe version 2>$null).Trim()
        if ($installed -like "0.16*") {
            Write-Host "[+] Zig $installed already present" -ForegroundColor Green
            $zigOk = $true
        } else {
            Write-Host "[!] Zig $installed present but 0.16 required - reinstalling" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Existing Zig is not runnable - reinstalling" -ForegroundColor Yellow
    }
}

if (-not $zigOk) {
    # Aether's CONTEXT handling assumes the AMD64 layout, so build x86_64 even
    # on ARM64 hosts and let Windows emulate it.
    $zigArch = "x86_64"
    $zigArchive = "zig-$zigArch-windows-$ZigVersion.zip"
    $zigUrls = @(
        "https://ziglang.org/download/$ZigVersion/$zigArchive",
        # Older release layouts used zig-windows-<arch>-<ver>.zip
        "https://ziglang.org/download/$ZigVersion/zig-windows-$zigArch-$ZigVersion.zip"
    )

    $tempZip = "$env:TEMP\$zigArchive"
    $got = $false
    foreach ($url in $zigUrls) {
        try {
            Write-Host "[*] Downloading Zig $ZigVersion ($zigArch)..." -ForegroundColor Yellow
            Write-Host "    $url" -ForegroundColor DarkGray
            Invoke-WebRequest -Uri $url -OutFile $tempZip -UseBasicParsing -TimeoutSec 600
            $got = $true
            break
        } catch {
            Write-Host "    [-] $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }

    if (-not $got) {
        Write-Host "[!] Could not download Zig - skipping Aether install" -ForegroundColor Red
        Write-Host "    Install Zig $ZigVersion manually to $ZigRoot and re-run this script." -ForegroundColor DarkGray
        exit 0
    }

    Write-Host "[*] Extracting Zig..." -ForegroundColor Yellow
    $extractTo = "$env:TEMP\zig-extract"
    if (Test-Path $extractTo) { Remove-Item $extractTo -Recurse -Force }
    Expand-Archive -Path $tempZip -DestinationPath $extractTo -Force

    # The archive contains a single versioned top-level directory.
    $inner = Get-ChildItem $extractTo -Directory | Select-Object -First 1
    if (Test-Path $ZigRoot) { Remove-Item $ZigRoot -Recurse -Force }
    Move-Item $inner.FullName $ZigRoot -Force
    Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
    Remove-Item $extractTo -Recurse -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $zigExe)) {
        Write-Host "[!] Zig extraction failed - skipping Aether install" -ForegroundColor Red
        exit 0
    }
    Write-Host "[+] Zig installed at $zigExe" -ForegroundColor Green
}

# --- Fetch source ---
$git = Get-Command git -ErrorAction SilentlyContinue
if (Test-Path $SourceDir) {
    Remove-Item $SourceDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($git) {
    Write-Host "[*] Cloning Aether source..." -ForegroundColor Yellow
    & git clone --depth 1 $RepoUrl $SourceDir 2>&1 | Out-Null
} else {
    Write-Host "[*] git not found - downloading source archive..." -ForegroundColor Yellow
    $tarball = "$env:TEMP\aether-main.zip"
    try {
        Invoke-WebRequest -Uri "$RepoUrl/archive/refs/heads/main.zip" `
            -OutFile $tarball -UseBasicParsing -TimeoutSec 300
        $extractTo = "$env:TEMP\aether-extract"
        if (Test-Path $extractTo) { Remove-Item $extractTo -Recurse -Force }
        Expand-Archive -Path $tarball -DestinationPath $extractTo -Force
        $inner = Get-ChildItem $extractTo -Directory | Select-Object -First 1
        Move-Item $inner.FullName $SourceDir -Force
        Remove-Item $tarball -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[!] Source download failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 0
    }
}

if (-not (Test-Path "$SourceDir\build.zig")) {
    Write-Host "[!] Aether source incomplete (no build.zig) - skipping" -ForegroundColor Red
    exit 0
}

# --- Build ---
Write-Host "[*] Building Aether (ReleaseSafe)..." -ForegroundColor Yellow
Push-Location $SourceDir
try {
    & $zigExe build -Doptimize=ReleaseSafe 2>&1 | ForEach-Object {
        Write-Host "    $_" -ForegroundColor DarkGray
    }
} finally {
    Pop-Location
}

$built = "$SourceDir\zig-out\bin\Aether.exe"
if (-not (Test-Path $built)) {
    Write-Host "[!] Build produced no Aether.exe - skipping" -ForegroundColor Red
    exit 0
}

Copy-Item $built $ExePath -Force

# Signature rules are loaded at runtime from the rules directory.
if (Test-Path "$SourceDir\rules") {
    New-Item -ItemType Directory -Path "$ToolRoot\rules" -Force | Out-Null
    Copy-Item "$SourceDir\rules\*.json" "$ToolRoot\rules\" -Force
    # @() so .Count also works for zero or one file under StrictMode.
    $ruleCount = @(Get-ChildItem "$ToolRoot\rules\*.json" -ErrorAction SilentlyContinue).Count
    Write-Host "[+] Installed $ruleCount signature rule file(s)" -ForegroundColor Green
}

# --- Verify ---
try {
    $help = & $ExePath --help 2>&1 | Out-String
    if ($help -match "Aether|--scan") {
        Write-Host "[+] Aether responds to --help" -ForegroundColor Green
    } else {
        Write-Host "[!] Unexpected --help output" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Could not run Aether.exe: $($_.Exception.Message)" -ForegroundColor Yellow
}

$size = [math]::Round((Get-Item $ExePath).Length / 1KB)
Write-Host ""
Write-Host "[+] Aether installed" -ForegroundColor Green
Write-Host "    Binary: $ExePath ($size KB)" -ForegroundColor DarkGray
Write-Host "    Rules:  $ToolRoot\rules" -ForegroundColor DarkGray
Write-Host "    Usage:  Aether.exe --scan --pid <PID> --json" -ForegroundColor DarkGray
Write-Host "            Aether.exe --scan-all --json" -ForegroundColor DarkGray
Write-Host "    Note:   scanning other users' processes requires Administrator" -ForegroundColor DarkGray
