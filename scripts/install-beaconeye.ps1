# install-beaconeye.ps1
# Downloads and installs BeaconEye (CobaltStrike beacon memory scanner)
#
# Source: https://github.com/CCob/BeaconEye
#
# BeaconEye scans process memory for CobaltStrike beacon configurations:
#   - Identifies active beacons in memory
#   - Extracts beacon config (C2 servers, sleep time, jitter, etc.)
#   - Works against sleep-masked and encoded beacons
#   - Supports scanning specific PIDs or all processes
#
# Expected path: C:\tools\BeaconEye\BeaconEye.exe
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing BeaconEye ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$installDir = "C:\tools\BeaconEye"
$binDir = "$installDir"
$exePath = "$binDir\BeaconEye.exe"

# Check if already installed
if (Test-Path $exePath) {
    Write-Host "[+] BeaconEye already installed at $exePath" -ForegroundColor Green
    exit 0
}

New-Item -ItemType Directory -Path $binDir -Force | Out-Null

# --- Try downloading pre-built release from GitHub ---
$downloaded = $false
$releaseUrls = @(
    "https://github.com/CCob/BeaconEye/releases/latest/download/BeaconEye.zip",
    "https://github.com/CCob/BeaconEye/releases/download/v1.0/BeaconEye.zip",
    "https://github.com/CCob/BeaconEye/releases/latest/download/BeaconEye-net6.0-win-x64.zip"
)

foreach ($url in $releaseUrls) {
    if ($downloaded) { break }
    try {
        Write-Host "[*] Trying: $url" -ForegroundColor Gray
        $zipPath = "$env:TEMP\BeaconEye.zip"
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -TimeoutSec 30

        # Extract
        $extractDir = "$env:TEMP\BeaconEye_extract"
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

        # Find the executable
        $foundExe = Get-ChildItem -Path $extractDir -Recurse -Filter "BeaconEye.exe" | Select-Object -First 1
        if ($foundExe) {
            # Copy all files from the same directory (includes dependencies)
            Copy-Item -Path "$($foundExe.DirectoryName)\*" -Destination $binDir -Recurse -Force
            $downloaded = $true
            Write-Host "[+] BeaconEye downloaded from release" -ForegroundColor Green
        } else {
            Write-Host "[!] BeaconEye.exe not found in archive" -ForegroundColor Yellow
        }

        # Cleanup
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[!] Download failed: $_" -ForegroundColor Yellow
    }
}

# --- Fallback: build from source ---
if (-not $downloaded) {
    Write-Host "[*] Pre-built release not available, trying to build from source..." -ForegroundColor Yellow
    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    $git = Get-Command git -ErrorAction SilentlyContinue

    if ($dotnet -and $git) {
        try {
            $srcDir = "$env:TEMP\BeaconEye_src"
            Remove-Item $srcDir -Recurse -Force -ErrorAction SilentlyContinue

            Write-Host "[*] Cloning BeaconEye repository..." -ForegroundColor Yellow
            & git clone --depth 1 "https://github.com/CCob/BeaconEye.git" $srcDir 2>$null

            $csproj = Get-ChildItem -Path $srcDir -Recurse -Filter "BeaconEye.csproj" | Select-Object -First 1
            if (-not $csproj) {
                # Try .sln file
                $sln = Get-ChildItem -Path $srcDir -Recurse -Filter "*.sln" | Select-Object -First 1
                if ($sln) {
                    Write-Host "[*] Building BeaconEye solution..." -ForegroundColor Yellow
                    & dotnet publish $sln.FullName -c Release -o $binDir --self-contained true -r win-x64 2>$null
                }
            } else {
                Write-Host "[*] Building BeaconEye project..." -ForegroundColor Yellow
                & dotnet publish $csproj.FullName -c Release -o $binDir --self-contained true -r win-x64 2>$null
            }

            if (Test-Path $exePath) {
                $downloaded = $true
                Write-Host "[+] BeaconEye built from source" -ForegroundColor Green
            } else {
                Write-Host "[!] Build completed but BeaconEye.exe not found at expected path" -ForegroundColor Yellow
                # List what was produced
                Get-ChildItem -Path $binDir -Filter "*.exe" | ForEach-Object {
                    Write-Host "    Found: $($_.Name)" -ForegroundColor Gray
                }
            }

            Remove-Item $srcDir -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "[!] Build from source failed: $_" -ForegroundColor Yellow
        }
    } else {
        if (-not $dotnet) { Write-Host "[!] dotnet SDK not found" -ForegroundColor Yellow }
        if (-not $git) { Write-Host "[!] git not found" -ForegroundColor Yellow }
        Write-Host "[!] Cannot build from source without dotnet SDK and git" -ForegroundColor Yellow
    }
}

# --- Add Windows Defender exclusion ---
if (Test-Path $exePath) {
    try {
        Add-MpPreference -ExclusionPath $installDir -ErrorAction SilentlyContinue
        Write-Host "[+] Added Defender exclusion for $installDir" -ForegroundColor Green
    } catch {
        Write-Host "[!] Could not add Defender exclusion (non-critical)" -ForegroundColor Yellow
    }
}

# --- Summary ---
Write-Host ""
Write-Host "=== BeaconEye Installation Summary ===" -ForegroundColor Cyan
if (Test-Path $exePath) {
    Write-Host "[+] BeaconEye: INSTALLED at $exePath" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Usage:" -ForegroundColor White
    Write-Host "    BeaconEye.exe scan              # Scan all processes" -ForegroundColor DarkGray
    Write-Host "    BeaconEye.exe scan --pid 1234   # Scan specific PID" -ForegroundColor DarkGray
} else {
    Write-Host "[-] BeaconEye: NOT INSTALLED" -ForegroundColor Red
    Write-Host "    Manual install: place BeaconEye.exe at $exePath" -ForegroundColor Red
}
Write-Host ""
