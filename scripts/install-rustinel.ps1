# install-rustinel.ps1
# Downloads and installs Rustinel (Sigma/YARA/IOC-based EDR), pinned to v1.1.1
#
# Rustinel provides:
#   - ETW-based telemetry collection
#   - Sigma rule detection
#   - YARA memory scanning
#   - IOC matching (hashes, IPs, domains, paths)
#   - Active response (optional process termination)
#   - ECS 9.3.0 NDJSON alert output
#
# Run as Administrator
#
# Parameters:
#   -Version <x.y.z>  release to install (default: the pin, 1.1.1)
#   -Force            replace an existing install (used by the tool updates).
#                     Only rustinel.exe is replaced; rules\, logs\, alerts\ and
#                     config.toml stay. The Rustinel task, the nssm service
#                     "Rustinel" and any rustinel process are stopped first and
#                     NOT restarted: the caller starts them again.
#
# After each successful install the release tag is written to
# C:\tools\rustinel\tdc-release.txt.

param(
    [string]$Version = "1.1.1",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Host "=== Installing Rustinel ===" -ForegroundColor Cyan

# Architecture detection
# OS architecture: the registry holds the real value; the process environment
# says AMD64 for children of an emulated x64 process (e.g. the web UI's Python)
$osArch = $null
try {
    $osArch = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PROCESSOR_ARCHITECTURE -ErrorAction Stop).PROCESSOR_ARCHITECTURE
} catch { $osArch = $null }
if (-not $osArch) { $osArch = $env:PROCESSOR_ARCHITEW6432 }
if (-not $osArch) { $osArch = $env:PROCESSOR_ARCHITECTURE }
$isArm64 = ($osArch -eq "ARM64")
if ($isArm64) {
    Write-Host "[!] ARM64 detected - Rustinel has no native ARM64 build" -ForegroundColor Yellow
    Write-Host "[*] Installing x86_64 build (runs under Windows ARM emulation layer)" -ForegroundColor Yellow
    Write-Host "[*] Note: ETW tracing should work under emulation but with slight overhead" -ForegroundColor Yellow
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    Write-Host "[!] -Version must look like 1.1.1 (got '$Version')" -ForegroundColor Red
    exit 1
}
$rustinelVersion = $Version
$rustinelInstallDir = "C:\tools\rustinel"
$rustinelZipUrl = "https://github.com/Karib0u/rustinel/releases/download/v${rustinelVersion}/rustinel-${rustinelVersion}-x86_64-pc-windows-msvc.zip"
$rustinelZipPath = "$env:TEMP\rustinel-${rustinelVersion}-x86_64-pc-windows-msvc.zip"

# Check if already installed
$replaceOnly = $false
if (Test-Path "$rustinelInstallDir\rustinel.exe") {
    if (-not $Force) {
        Write-Host "[+] Rustinel already installed at $rustinelInstallDir" -ForegroundColor Green
        exit 0
    }
    $replaceOnly = $true
}

# Download Rustinel
Write-Host "[*] Downloading Rustinel v${rustinelVersion}..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $rustinelZipUrl -OutFile $rustinelZipPath -UseBasicParsing

# Update: swap rustinel.exe only, rules and config stay
if ($replaceOnly) {
    Write-Host "[*] Extracting Rustinel v${rustinelVersion}..." -ForegroundColor Yellow
    $updateDir = "$env:TEMP\rustinel-update"
    if (Test-Path $updateDir) { Remove-Item $updateDir -Recurse -Force }
    Expand-Archive -Path $rustinelZipPath -DestinationPath $updateDir -Force
    $newExe = Get-ChildItem -Path $updateDir -Recurse -Filter "rustinel.exe" | Select-Object -First 1
    if (-not $newExe) {
        Remove-Item $updateDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $rustinelZipPath -Force -ErrorAction SilentlyContinue
        Write-Host "[!] rustinel.exe not found in the archive - install left as it was" -ForegroundColor Red
        exit 1
    }

    # Whatever runs rustinel.exe has to stop before the file can be replaced.
    Write-Host "[*] Stopping Rustinel..." -ForegroundColor Yellow
    Stop-ScheduledTask -TaskName "Rustinel" -ErrorAction SilentlyContinue
    if (Get-Service -Name "Rustinel" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "Rustinel" -Force -ErrorAction SilentlyContinue
    }
    Stop-Process -Name "rustinel" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Copy-Item -Path $newExe.FullName -Destination "$rustinelInstallDir\rustinel.exe" -Force
    Set-Content -Path "$rustinelInstallDir\tdc-release.txt" -Value "v${rustinelVersion}" -Encoding ASCII
    Remove-Item $updateDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $rustinelZipPath -Force -ErrorAction SilentlyContinue

    Write-Host "[+] Rustinel replaced by v${rustinelVersion} (rules and config kept)" -ForegroundColor Green
    Write-Host "    Binary: $rustinelInstallDir\rustinel.exe" -ForegroundColor Gray
    exit 0
}

# Extract
Write-Host "[*] Extracting Rustinel..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $rustinelInstallDir -Force | Out-Null
Expand-Archive -Path $rustinelZipPath -DestinationPath $rustinelInstallDir -Force

# Handle nested directory from ZIP extraction
$nestedDir = Get-ChildItem -Path $rustinelInstallDir -Directory | Where-Object { $_.Name -like "rustinel*" } | Select-Object -First 1
if ($nestedDir) {
    # Move contents up one level
    Get-ChildItem -Path $nestedDir.FullName | Move-Item -Destination $rustinelInstallDir -Force
    Remove-Item $nestedDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
}

# Verify binary exists
if (-not (Test-Path "$rustinelInstallDir\rustinel.exe")) {
    Write-Host "[!] rustinel.exe not found after extraction. Listing contents:" -ForegroundColor Red
    Get-ChildItem -Path $rustinelInstallDir -Recurse | ForEach-Object { Write-Host "    $($_.FullName)" }
    exit 1
}

# Add to PATH
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*rustinel*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$rustinelInstallDir", "Machine")
    $env:Path = "$rustinelInstallDir;$env:Path"
}

# Create rules directories
$rulesDirs = @(
    "$rustinelInstallDir\rules\sigma",
    "$rustinelInstallDir\rules\yara",
    "$rustinelInstallDir\rules\ioc"
)
foreach ($dir in $rulesDirs) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# Copy bundled detection rules from the project
$bundledRulesDir = "C:\vagrant\rules"
if (-not (Test-Path $bundledRulesDir)) {
    # Fallback: try relative to vagrant_config
    $bundledRulesDir = "C:\vagrant_config\..\rules"
    if (Test-Path $bundledRulesDir) {
        $bundledRulesDir = (Resolve-Path $bundledRulesDir -ErrorAction SilentlyContinue).Path
    }
}
if ($bundledRulesDir -and (Test-Path $bundledRulesDir)) {
    Write-Host "[*] Installing bundled Sigma rules..." -ForegroundColor Yellow
    if (Test-Path "$bundledRulesDir\sigma") {
        Copy-Item "$bundledRulesDir\sigma\*" "$rustinelInstallDir\rules\sigma\" -Force -Recurse
        $sigmaCount = (Get-ChildItem "$rustinelInstallDir\rules\sigma\*.yml").Count
        Write-Host "    Sigma rules: $sigmaCount" -ForegroundColor Gray
    }
    Write-Host "[*] Installing bundled YARA rules..." -ForegroundColor Yellow
    if (Test-Path "$bundledRulesDir\yara") {
        Copy-Item "$bundledRulesDir\yara\*" "$rustinelInstallDir\rules\yara\" -Force -Recurse
        $yaraCount = (Get-ChildItem "$rustinelInstallDir\rules\yara\*.yar").Count
        Write-Host "    YARA rules: $yaraCount" -ForegroundColor Gray
    }
} else {
    Write-Host "[!] Bundled rules not found - using empty rule dirs" -ForegroundColor Yellow
}

# Create empty IOC feed files (will be populated at runtime via web UI)
foreach ($iocFile in @("hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt")) {
    $iocPath = "$rustinelInstallDir\rules\ioc\$iocFile"
    if (-not (Test-Path $iocPath)) {
        New-Item -ItemType File -Path $iocPath -Force | Out-Null
    }
}

# Apply custom configuration if available
if (Test-Path "C:\vagrant_config\rustinel-config.toml") {
    Write-Host "[*] Applying custom Rustinel configuration..." -ForegroundColor Yellow
    Copy-Item "C:\vagrant_config\rustinel-config.toml" "$rustinelInstallDir\config.toml" -Force
}

# Create logs output directory (where alerts are written)
New-Item -ItemType Directory -Path "$rustinelInstallDir\logs" -Force | Out-Null

# Release marker (read by the tool updates)
Set-Content -Path "$rustinelInstallDir\tdc-release.txt" -Value "v${rustinelVersion}" -Encoding ASCII

# Clean up
Remove-Item $rustinelZipPath -Force -ErrorAction SilentlyContinue

Write-Host "[+] Rustinel v${rustinelVersion} installed at $rustinelInstallDir" -ForegroundColor Green
Write-Host "    Binary: $rustinelInstallDir\rustinel.exe" -ForegroundColor Gray
Write-Host "    Config: $rustinelInstallDir\config.toml" -ForegroundColor Gray
Write-Host "    Rules:  $rustinelInstallDir\rules\" -ForegroundColor Gray
