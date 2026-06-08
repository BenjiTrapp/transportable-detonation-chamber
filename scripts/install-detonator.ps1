# install-detonator.ps1
# Installs Detonator (Python orchestrator) and DetonatorAgent (.NET agent)
#
# Architecture:
#   - Detonator: Python web/REST server (ports 5000/8000)
#   - DetonatorAgent: .NET 8.0 agent that executes files and collects EDR logs (port 8080)
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Detonator + DetonatorAgent ===" -ForegroundColor Cyan

$detonatorDir = "C:\detonator"
$detonatorAgentDir = "C:\DetonatorAgent"

# --- Install DetonatorAgent ---
Write-Host "`n--- DetonatorAgent (.NET) ---" -ForegroundColor Cyan

if (Test-Path "$detonatorAgentDir\DetonatorAgent.csproj") {
    Write-Host "[+] DetonatorAgent source already present" -ForegroundColor Green
} else {
    Write-Host "[*] Cloning DetonatorAgent..." -ForegroundColor Yellow
    git clone https://github.com/dobin/DetonatorAgent.git $detonatorAgentDir
}

# Build DetonatorAgent
Write-Host "[*] Building DetonatorAgent..." -ForegroundColor Yellow
Push-Location $detonatorAgentDir
try {
    # Restore and build
    dotnet restore --verbosity quiet
    dotnet build --configuration Release --verbosity quiet

    # Publish as self-contained for reliability
    dotnet publish --configuration Release --output "$detonatorAgentDir\publish" --verbosity quiet

    if (Test-Path "$detonatorAgentDir\publish\DetonatorAgent.exe") {
        Write-Host "[+] DetonatorAgent built successfully" -ForegroundColor Green
    } elseif (Test-Path "$detonatorAgentDir\publish\DetonatorAgent.dll") {
        Write-Host "[+] DetonatorAgent built successfully (framework-dependent)" -ForegroundColor Green
    } else {
        Write-Host "[!] Build output not found, will use 'dotnet run' instead" -ForegroundColor Yellow
    }
} finally {
    Pop-Location
}

# --- Install Detonator ---
Write-Host "`n--- Detonator (Python) ---" -ForegroundColor Cyan

if (Test-Path "$detonatorDir\pyproject.toml") {
    Write-Host "[+] Detonator source already present" -ForegroundColor Green
} else {
    Write-Host "[*] Cloning Detonator..." -ForegroundColor Yellow
    git clone https://github.com/dobin/detonator.git $detonatorDir
}

# Set up Python virtual environment and install dependencies
Write-Host "[*] Setting up Python environment..." -ForegroundColor Yellow
Push-Location $detonatorDir
try {
    # Find Python - prefer Chocolatey install, fallback to PATH
    $pythonExe = "C:\Python312\python.exe"
    if (-not (Test-Path $pythonExe)) {
        $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    }
    if (-not $pythonExe -or -not (Test-Path $pythonExe)) {
        Write-Host "[!] Python not found - cannot set up Detonator" -ForegroundColor Red
        Pop-Location
        return
    }
    Write-Host "    Using Python: $pythonExe" -ForegroundColor Gray

    # Create venv
    if (-not (Test-Path "$detonatorDir\.venv\Scripts\python.exe")) {
        & $pythonExe -m venv "$detonatorDir\.venv"
    }

    # Verify venv is functional
    $venvPython = "$detonatorDir\.venv\Scripts\python.exe"
    $venvCheck = & $venvPython -c "print('ok')" 2>&1
    if ($venvCheck -notmatch "ok") {
        Write-Host "[*] Venv broken, recreating..." -ForegroundColor Yellow
        Remove-Item "$detonatorDir\.venv" -Recurse -Force
        & $pythonExe -m venv "$detonatorDir\.venv"
    }

    $venvPip = "$detonatorDir\.venv\Scripts\pip.exe"

    # Filter out problematic dependencies:
    # - crowdstrike-falconpy: version 4.0.3 doesn't exist on PyPI (latest is 1.x)
    # - uvloop: Linux-only, not available on Windows
    $reqFile = "$detonatorDir\requirements.txt"
    $localReqFile = "$detonatorDir\requirements-local.txt"
    if (Test-Path $reqFile) {
        $filteredReqs = Get-Content $reqFile | Where-Object {
            $_ -notmatch "^crowdstrike-falconpy==4\." -and $_ -notmatch "^uvloop"
        }
        Set-Content -Path $localReqFile -Value $filteredReqs
        Write-Host "[*] Filtered requirements (removed unavailable packages)" -ForegroundColor Yellow
    }

    # Install dependencies
    Write-Host "[*] Installing dependencies with pip..." -ForegroundColor Yellow
    & $venvPip install --upgrade pip --quiet 2>$null
    & $venvPip install -r $localReqFile --quiet
    # Install latest available crowdstrike-falconpy (without strict version pin)
    & $venvPip install crowdstrike-falconpy --quiet 2>$null

    # Create profiles_init.yaml from config or sample
    if (Test-Path "C:\vagrant_config\profiles_init.yaml") {
        Copy-Item "C:\vagrant_config\profiles_init.yaml" "$detonatorDir\profiles_init.yaml" -Force
        Write-Host "[+] Applied custom profiles_init.yaml" -ForegroundColor Green
    } elseif (-not (Test-Path "$detonatorDir\profiles_init.yaml")) {
        # Create default config pointing to localhost DetonatorAgent
        $profileContent = @"
localdetonator:
  type: Live
  comment: Local Detonation Chamber (Fibratus EDR)
  port: 8080
  vm_ip: 127.0.0.1

localdetonator_rustinel:
  type: Live
  comment: Local Detonation Chamber (Rustinel EDR)
  port: 8080
  vm_ip: 127.0.0.1
"@
        Set-Content -Path "$detonatorDir\profiles_init.yaml" -Value $profileContent
        Write-Host "[+] Created default profiles_init.yaml" -ForegroundColor Green
    }

    # Initialize the database
    Write-Host "[*] Initializing Detonator database..." -ForegroundColor Yellow
    & $venvPython migrate_profiles_yaml.py 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Database initialized" -ForegroundColor Green
    } else {
        Write-Host "[!] Database initialization had issues (may be first run)" -ForegroundColor Yellow
    }
} finally {
    Pop-Location
}

Write-Host "`n[+] Detonator + DetonatorAgent installation complete!" -ForegroundColor Green
Write-Host "    DetonatorAgent: $detonatorAgentDir" -ForegroundColor Gray
Write-Host "    Detonator:      $detonatorDir" -ForegroundColor Gray
