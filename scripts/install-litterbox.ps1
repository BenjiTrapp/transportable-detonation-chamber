# install-litterbox.ps1
# Installs LitterBox - self-hosted payload analysis sandbox for red teams
#
# LitterBox provides:
#   - Static analysis (PE-Sieve, Hollows-Hunter, Moneta, YARA, etc.)
#   - Dynamic/memory scanning (Patriot, Hunt-Sleeping-Beacons, RedEdr)
#   - Detection scoring with triggering-indicator breakdown
#   - EDR integration (Fibratus, Elastic Defend)
#   - MCP server for LLM-driven analysis
#   - Web UI on port 1337
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing LitterBox ===" -ForegroundColor Cyan

$litterboxDir = "C:\LitterBox"

# Check if already installed
if (Test-Path "$litterboxDir\litterbox.py") {
    Write-Host "[+] LitterBox already present at $litterboxDir" -ForegroundColor Green
    # Update to latest
    Write-Host "[*] Pulling latest changes..." -ForegroundColor Yellow
    Push-Location $litterboxDir
    git pull --ff-only 2>$null
    Pop-Location
} else {
    # Clone LitterBox
    Write-Host "[*] Cloning LitterBox..." -ForegroundColor Yellow
    git clone https://github.com/BlackSnufkin/LitterBox.git $litterboxDir
}

# Set up Python virtual environment
Write-Host "[*] Setting up Python virtual environment..." -ForegroundColor Yellow
Push-Location $litterboxDir
try {
    # Find Python - prefer Chocolatey install, fallback to PATH
    $pythonExe = "C:\Python312\python.exe"
    if (-not (Test-Path $pythonExe)) {
        $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    }
    if (-not $pythonExe -or -not (Test-Path $pythonExe)) {
        Write-Host "[!] Python not found - cannot set up LitterBox" -ForegroundColor Red
        Pop-Location
        return
    }
    Write-Host "    Using Python: $pythonExe" -ForegroundColor Gray

    # Create venv if it doesn't exist
    if (-not (Test-Path "$litterboxDir\venv\Scripts\python.exe")) {
        & $pythonExe -m venv "$litterboxDir\venv"
    }

    # Verify venv is functional
    $venvPython = "$litterboxDir\venv\Scripts\python.exe"
    $venvCheck = & $venvPython -c "print('ok')" 2>&1
    if ($venvCheck -notmatch "ok") {
        Write-Host "[*] Venv broken, recreating..." -ForegroundColor Yellow
        Remove-Item "$litterboxDir\venv" -Recurse -Force
        & $pythonExe -m venv "$litterboxDir\venv"
    }

    $venvPip = "$litterboxDir\venv\Scripts\pip.exe"

    # Install dependencies
    Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
    & $venvPip install --upgrade pip --quiet 2>$null
    & $venvPip install -r requirements.txt --quiet

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Python dependencies installed" -ForegroundColor Green
    } else {
        Write-Host "[!] Some dependencies may have failed - check manually" -ForegroundColor Yellow
    }
} finally {
    Pop-Location
}

# Patch LitterBox config to bind on all interfaces (0.0.0.0) so host can reach it
$configFile = "$litterboxDir\Config\config.yaml"
if (Test-Path $configFile) {
    $cfg = Get-Content $configFile -Raw
    if ($cfg -match 'host:\s*"127\.0\.0\.1"') {
        $cfg = $cfg -replace 'host:\s*"127\.0\.0\.1"', 'host: "0.0.0.0"'
        Set-Content -Path $configFile -Value $cfg
        Write-Host "[+] Patched LitterBox config to bind on 0.0.0.0" -ForegroundColor Green
    }
}

# Configure LitterBox EDR profile for Fibratus (local)
$edrProfilesDir = "$litterboxDir\Config\edr_profiles"
if (-not (Test-Path $edrProfilesDir)) {
    New-Item -ItemType Directory -Path $edrProfilesDir -Force | Out-Null
}

# Create a Fibratus EDR profile pointing to local Whiskers/DetonatorAgent
$fibratusProfilePath = "$edrProfilesDir\fibratus_local.yaml"
if (-not (Test-Path $fibratusProfilePath)) {
    Write-Host "[*] Creating Fibratus EDR profile..." -ForegroundColor Yellow
    $profileContent = @"
# LitterBox EDR Profile: Local Fibratus
# Dispatches payloads to the local Fibratus-instrumented environment
name: "Fibratus (Local)"
type: fibratus
host: 127.0.0.1
port: 8080
enabled: true
timeout: 60
description: "Local detonation chamber with Fibratus EDR"
"@
    Set-Content -Path $fibratusProfilePath -Value $profileContent
    Write-Host "[+] Fibratus EDR profile created" -ForegroundColor Green
}

# Configure LitterBox settings if config template exists
if (Test-Path "C:\vagrant_config\litterbox-config.yaml") {
    Write-Host "[*] Applying custom LitterBox configuration..." -ForegroundColor Yellow
    Copy-Item "C:\vagrant_config\litterbox-config.yaml" "$litterboxDir\Config\config.yaml" -Force
}

# Verify scanners are present
$scannersDir = "$litterboxDir\Scanners"
if (Test-Path $scannersDir) {
    $scannerCount = (Get-ChildItem -Path $scannersDir -Directory).Count
    Write-Host "[+] Found $scannerCount scanner directories" -ForegroundColor Green
} else {
    Write-Host "[!] Scanners directory not found - bundled scanners may be missing" -ForegroundColor Yellow
}

# Add Windows Defender exclusion for LitterBox
Add-MpPreference -ExclusionPath $litterboxDir -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "$litterboxDir\Scanners" -ErrorAction SilentlyContinue

# Configure firewall rule for LitterBox web UI
New-NetFirewallRule -DisplayName "LitterBox Web UI" -Direction Inbound -LocalPort 1337 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null

Write-Host "`n[+] LitterBox installation complete!" -ForegroundColor Green
Write-Host "    Directory: $litterboxDir" -ForegroundColor Gray
Write-Host "    Web UI:    http://localhost:1337" -ForegroundColor Gray
Write-Host "    Scanners:  $scannersDir" -ForegroundColor Gray
Write-Host "    EDR Profiles: $edrProfilesDir" -ForegroundColor Gray
