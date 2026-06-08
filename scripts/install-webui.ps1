# install-webui.ps1
# Installs the Detonation Chamber unified web UI
#
# The web UI aggregates data from all tools:
#   - Rustinel alerts (NDJSON files)
#   - Fibratus (via Windows Event Log)
#   - DetonatorAgent (REST API proxy)
#   - Detonator (REST API proxy)
#   - LitterBox (REST API proxy)
#
# Runs on port 9000
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Detonation Chamber Web UI ===" -ForegroundColor Cyan

$webuiDir = "C:\DetonationChamberUI"
$sourceDir = "C:\vagrant\webui"  # Synced from host via Vagrant

# Copy web UI files
if (Test-Path $sourceDir) {
    Write-Host "[*] Copying web UI from synced folder..." -ForegroundColor Yellow
    if (Test-Path $webuiDir) {
        Remove-Item $webuiDir -Recurse -Force
    }
    Copy-Item $sourceDir $webuiDir -Recurse -Force
} elseif (Test-Path "C:\vagrant_config\..\webui") {
    $altSource = (Resolve-Path "C:\vagrant_config\..\webui" -ErrorAction SilentlyContinue).Path
    if ($altSource -and (Test-Path $altSource)) {
        Write-Host "[*] Copying web UI from config parent..." -ForegroundColor Yellow
        Copy-Item $altSource $webuiDir -Recurse -Force
    }
} else {
    Write-Host "[!] Web UI source not found in synced folders" -ForegroundColor Yellow
    Write-Host "    Creating from embedded content..." -ForegroundColor Yellow
    # If not synced, the web UI should already be at C:\DetonationChamberUI
    if (-not (Test-Path "$webuiDir\app.py")) {
        Write-Host "[!] Web UI not available - skipping" -ForegroundColor Red
        exit 0
    }
}

# Set up Python virtual environment for the web UI
Write-Host "[*] Setting up Python environment for web UI..." -ForegroundColor Yellow

# Find Python - prefer Chocolatey install, fallback to PATH
$pythonExe = "C:\Python312\python.exe"
if (-not (Test-Path $pythonExe)) {
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
}
if (-not $pythonExe -or -not (Test-Path $pythonExe)) {
    Write-Host "[!] Python not found - cannot set up web UI venv" -ForegroundColor Red
    exit 1
}
Write-Host "    Using Python: $pythonExe" -ForegroundColor Gray

if (-not (Test-Path "$webuiDir\venv\Scripts\python.exe")) {
    & $pythonExe -m venv "$webuiDir\venv"
}

# Verify venv is functional (not pointing to a stale path)
$venvPython = "$webuiDir\venv\Scripts\python.exe"
$venvCheck = & $venvPython -c "print('ok')" 2>&1
if ($venvCheck -notmatch "ok") {
    Write-Host "[*] Venv broken, recreating..." -ForegroundColor Yellow
    Remove-Item "$webuiDir\venv" -Recurse -Force
    & $pythonExe -m venv "$webuiDir\venv"
}

$venvPip = "$webuiDir\venv\Scripts\pip.exe"
& $venvPip install --upgrade pip --quiet 2>$null
& $venvPip install -r "$webuiDir\requirements.txt" --quiet

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Web UI dependencies installed" -ForegroundColor Green
} else {
    Write-Host "[!] Some dependencies may have failed" -ForegroundColor Yellow
}

# Configure firewall
New-NetFirewallRule -DisplayName "Detonation Chamber UI" -Direction Inbound -LocalPort 9000 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null

Write-Host "[+] Web UI installed at $webuiDir" -ForegroundColor Green
Write-Host "    URL: http://localhost:9000" -ForegroundColor Gray
