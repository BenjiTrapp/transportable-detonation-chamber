# install-scanner-tools.ps1
# Downloads and installs ThreatCheck + DefenderCheck (AV signature scanning tools)
#
# ThreatCheck (by rasta-mouse):
#   - Identifies exact byte sequences that trigger AV/AMSI detection
#   - Supports Defender and AMSI scan engines
#   - Binary splitting approach to pinpoint signature matches
#
# DefenderCheck (by matterpreter):
#   - Similar byte-splitting approach specifically for Windows Defender
#   - Predecessor to ThreatCheck, still useful for quick checks
#
# Expected paths after install:
#   C:\tools\ThreatCheck\bin\ThreatCheck.exe
#   C:\tools\DefenderCheck\bin\DefenderCheck.exe
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Scanner Tools (ThreatCheck + DefenderCheck) ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- ThreatCheck ---
$tcInstallDir = "C:\tools\ThreatCheck"
$tcBinDir = "$tcInstallDir\bin"
$tcExe = "$tcBinDir\ThreatCheck.exe"

if (Test-Path $tcExe) {
    Write-Host "[+] ThreatCheck already installed at $tcExe" -ForegroundColor Green
} else {
    Write-Host "[*] Installing ThreatCheck..." -ForegroundColor Yellow

    New-Item -ItemType Directory -Path $tcBinDir -Force | Out-Null

    # Try downloading pre-built release from GitHub
    $tcDownloaded = $false
    $tcReleaseUrls = @(
        "https://github.com/rasta-mouse/ThreatCheck/releases/latest/download/ThreatCheck.zip",
        "https://github.com/rasta-mouse/ThreatCheck/releases/download/v1.0.0/ThreatCheck.zip"
    )

    foreach ($url in $tcReleaseUrls) {
        if ($tcDownloaded) { break }
        try {
            Write-Host "[*] Trying: $url" -ForegroundColor Gray
            $zipPath = "$env:TEMP\ThreatCheck.zip"
            Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -TimeoutSec 30
            Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\ThreatCheck_extract" -Force

            # Find ThreatCheck.exe in extracted contents (may be nested)
            $foundExe = Get-ChildItem -Path "$env:TEMP\ThreatCheck_extract" -Recurse -Filter "ThreatCheck.exe" | Select-Object -First 1
            if ($foundExe) {
                # Copy all files from the same directory (includes dependencies)
                Copy-Item -Path "$($foundExe.DirectoryName)\*" -Destination $tcBinDir -Recurse -Force
                $tcDownloaded = $true
                Write-Host "[+] ThreatCheck downloaded from release" -ForegroundColor Green
            } else {
                Write-Host "[!] ThreatCheck.exe not found in archive" -ForegroundColor Yellow
            }

            # Cleanup
            Remove-Item "$env:TEMP\ThreatCheck_extract" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "[!] Download failed: $_" -ForegroundColor Yellow
        }
    }

    # Fallback: build from source if dotnet SDK is available
    if (-not $tcDownloaded) {
        Write-Host "[*] Pre-built release not available, trying to build from source..." -ForegroundColor Yellow
        $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
        if ($dotnet) {
            try {
                $tcSrcDir = "$env:TEMP\ThreatCheck_src"
                Remove-Item $tcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
                git clone --depth 1 "https://github.com/rasta-mouse/ThreatCheck.git" $tcSrcDir 2>$null

                $csproj = Get-ChildItem -Path $tcSrcDir -Recurse -Filter "ThreatCheck.csproj" | Select-Object -First 1
                if ($csproj) {
                    Write-Host "[*] Building ThreatCheck with dotnet..." -ForegroundColor Yellow
                    & dotnet publish $csproj.FullName -c Release -o $tcBinDir --self-contained false 2>$null
                    if (Test-Path $tcExe) {
                        $tcDownloaded = $true
                        Write-Host "[+] ThreatCheck built from source" -ForegroundColor Green
                    }
                }
                Remove-Item $tcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[!] Build from source failed: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[!] dotnet SDK not found - cannot build from source" -ForegroundColor Yellow
        }
    }

    if (-not $tcDownloaded) {
        Write-Host "[!] ThreatCheck installation FAILED - no download source available" -ForegroundColor Red
        Write-Host "    Manual install: place ThreatCheck.exe at $tcExe" -ForegroundColor Red
    }
}

# --- DefenderCheck ---
$dcInstallDir = "C:\tools\DefenderCheck"
$dcBinDir = "$dcInstallDir\bin"
$dcExe = "$dcBinDir\DefenderCheck.exe"

if (Test-Path $dcExe) {
    Write-Host "[+] DefenderCheck already installed at $dcExe" -ForegroundColor Green
} else {
    Write-Host "[*] Installing DefenderCheck..." -ForegroundColor Yellow

    New-Item -ItemType Directory -Path $dcBinDir -Force | Out-Null

    # Try downloading pre-built release from GitHub
    $dcDownloaded = $false
    $dcReleaseUrls = @(
        "https://github.com/matterpreter/DefenderCheck/releases/latest/download/DefenderCheck.zip",
        "https://github.com/matterpreter/DefenderCheck/releases/latest/download/DefenderCheck.exe"
    )

    foreach ($url in $dcReleaseUrls) {
        if ($dcDownloaded) { break }
        try {
            Write-Host "[*] Trying: $url" -ForegroundColor Gray
            if ($url.EndsWith(".zip")) {
                $zipPath = "$env:TEMP\DefenderCheck.zip"
                Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -TimeoutSec 30
                Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\DefenderCheck_extract" -Force

                $foundExe = Get-ChildItem -Path "$env:TEMP\DefenderCheck_extract" -Recurse -Filter "DefenderCheck.exe" | Select-Object -First 1
                if ($foundExe) {
                    Copy-Item -Path "$($foundExe.DirectoryName)\*" -Destination $dcBinDir -Recurse -Force
                    $dcDownloaded = $true
                    Write-Host "[+] DefenderCheck downloaded from release" -ForegroundColor Green
                }
                Remove-Item "$env:TEMP\DefenderCheck_extract" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            } else {
                # Direct exe download
                Invoke-WebRequest -Uri $url -OutFile $dcExe -UseBasicParsing -TimeoutSec 30
                if (Test-Path $dcExe) {
                    $dcDownloaded = $true
                    Write-Host "[+] DefenderCheck downloaded directly" -ForegroundColor Green
                }
            }
        } catch {
            Write-Host "[!] Download failed: $_" -ForegroundColor Yellow
        }
    }

    # Fallback: build from source
    if (-not $dcDownloaded) {
        Write-Host "[*] Pre-built release not available, trying to build from source..." -ForegroundColor Yellow
        $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
        if ($dotnet) {
            try {
                $dcSrcDir = "$env:TEMP\DefenderCheck_src"
                Remove-Item $dcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
                git clone --depth 1 "https://github.com/matterpreter/DefenderCheck.git" $dcSrcDir 2>$null

                $csproj = Get-ChildItem -Path $dcSrcDir -Recurse -Filter "DefenderCheck.csproj" | Select-Object -First 1
                if ($csproj) {
                    Write-Host "[*] Building DefenderCheck with dotnet..." -ForegroundColor Yellow
                    & dotnet publish $csproj.FullName -c Release -o $dcBinDir --self-contained false 2>$null
                    if (Test-Path $dcExe) {
                        $dcDownloaded = $true
                        Write-Host "[+] DefenderCheck built from source" -ForegroundColor Green
                    }
                }
                Remove-Item $dcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[!] Build from source failed: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[!] dotnet SDK not found - cannot build from source" -ForegroundColor Yellow
        }
    }

    if (-not $dcDownloaded) {
        Write-Host "[!] DefenderCheck installation FAILED - no download source available" -ForegroundColor Red
        Write-Host "    Manual install: place DefenderCheck.exe at $dcExe" -ForegroundColor Red
    }
}

# --- Summary ---
Write-Host ""
Write-Host "=== Scanner Tools Installation Summary ===" -ForegroundColor Cyan
if (Test-Path $tcExe) {
    Write-Host "[+] ThreatCheck:   INSTALLED at $tcExe" -ForegroundColor Green
} else {
    Write-Host "[-] ThreatCheck:   NOT INSTALLED" -ForegroundColor Red
}
if (Test-Path $dcExe) {
    Write-Host "[+] DefenderCheck: INSTALLED at $dcExe" -ForegroundColor Green
} else {
    Write-Host "[-] DefenderCheck: NOT INSTALLED" -ForegroundColor Red
}
Write-Host ""
