# install-thezoo.ps1
# Installs theZoo malware sample repository and theZoo-WebUI
#
# Components:
#   - theZoo (ytisf/theZoo): Malware sample collection with Python CLI
#   - theZoo-WebUI (kawaiipantsu/theZoo-WebUI): PHP web frontend for browsing samples
#
# Serves on port 8888 via PHP built-in server
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing theZoo + theZoo-WebUI ===" -ForegroundColor Cyan

$ZooRoot = "C:\tools\theZoo-WebUI"
$ZooRepo = "$ZooRoot\theZoo"
$ZooPort = 8888

# --- Install PHP (required for theZoo-WebUI) ---
if (-not (Get-Command php -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Installing PHP via Chocolatey..." -ForegroundColor Yellow
    choco install php -y --no-progress --params "/InstallDir:C:\tools\php"
    # Enable required extensions
    $phpIni = "C:\tools\php\php.ini"
    if (-not (Test-Path $phpIni)) {
        Copy-Item "C:\tools\php\php.ini-development" $phpIni -ErrorAction SilentlyContinue
        if (-not (Test-Path $phpIni)) {
            Copy-Item "C:\tools\php\php.ini-production" $phpIni -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path $phpIni) {
        # Append a clean extensions block at the end of php.ini
        $iniContent = Get-Content $phpIni -Raw
        if ($iniContent -notmatch "Detonation Chamber Extensions") {
            $extBlock = @"

; === Detonation Chamber Extensions ===
extension_dir = "C:\tools\php\ext"
extension=curl
extension=sqlite3
extension=pdo_sqlite
extension=zip
extension=mbstring
extension=openssl
extension=fileinfo
error_reporting = E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING
display_errors = Off
"@
            Add-Content $phpIni $extBlock
        }
        Write-Host "[+] PHP extensions configured (curl, sqlite3, pdo_sqlite, zip, mbstring, openssl, fileinfo)" -ForegroundColor Green
    }
    $env:Path = "C:\tools\php;$env:Path"
    [Environment]::SetEnvironmentVariable("Path", "C:\tools\php;$([Environment]::GetEnvironmentVariable('Path', 'Machine'))", "Machine")
} else {
    Write-Host "[+] PHP already installed: $(php --version | Select-Object -First 1)" -ForegroundColor Green
}

# --- Clone theZoo-WebUI ---
if (-not (Test-Path "$ZooRoot\index.php")) {
    Write-Host "[*] Cloning theZoo-WebUI..." -ForegroundColor Yellow
    if (Test-Path $ZooRoot) { Remove-Item $ZooRoot -Recurse -Force }
    git clone "https://github.com/kawaiipantsu/theZoo-WebUI.git" $ZooRoot 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to clone theZoo-WebUI" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] theZoo-WebUI cloned to $ZooRoot" -ForegroundColor Green
} else {
    Write-Host "[+] theZoo-WebUI already present at $ZooRoot" -ForegroundColor Green
    # Pull latest
    Push-Location $ZooRoot
    git pull --ff-only 2>&1 | Out-Null
    Pop-Location
}

# --- Clone theZoo repository ---
if (-not (Test-Path "$ZooRepo\theZoo.py")) {
    Write-Host "[*] Cloning theZoo malware repository..." -ForegroundColor Yellow
    if (Test-Path $ZooRepo) { Remove-Item $ZooRepo -Recurse -Force }
    git clone "https://github.com/ytisf/theZoo.git" $ZooRepo 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to clone theZoo" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] theZoo cloned to $ZooRepo" -ForegroundColor Green
} else {
    Write-Host "[+] theZoo already present at $ZooRepo" -ForegroundColor Green
    # Pull latest
    Push-Location $ZooRepo
    git pull --ff-only 2>&1 | Out-Null
    Pop-Location
}

# --- Install theZoo Python dependencies ---
Write-Host "[*] Installing theZoo Python requirements..." -ForegroundColor Yellow
$pythonExe = $null
foreach ($p in @("python3", "python", "py")) {
    $found = Get-Command $p -ErrorAction SilentlyContinue
    if ($found) { $pythonExe = $found.Source; break }
}
if (-not $pythonExe) {
    # Fallback: check common install paths
    $candidates = @(
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe",
        "$env:LocalAppData\Programs\Python\Python312\python.exe",
        "$env:LocalAppData\Programs\Python\Python311\python.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $pythonExe = $c; break }
    }
}
if ($pythonExe) {
    $reqFile = "$ZooRepo\requirements.txt"
    if (Test-Path $reqFile) {
        & $pythonExe -m pip install --user -r $reqFile 2>&1 | Out-Null
        Write-Host "[+] theZoo Python dependencies installed" -ForegroundColor Green
    } else {
        Write-Host "[!] No requirements.txt found in theZoo" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] Python not found - theZoo CLI won't work (WebUI still functional)" -ForegroundColor Yellow
}

# --- Configure theZoo-WebUI ---
# Update config.inc.php to point to the theZoo directory
$configFile = "$ZooRoot\config.inc.php"
if (Test-Path $configFile) {
    $config = Get-Content $configFile -Raw
    # Set theZoo path - the WebUI expects theZoo to be in a subdirectory called 'theZoo'
    # Default config usually has: $thezoo_path = "./theZoo";
    # On Windows we keep it relative since the PHP server runs from $ZooRoot
    if ($config -match "thezoo_path") {
        Write-Host "[+] theZoo-WebUI config already has thezoo_path set" -ForegroundColor Green
    }
} else {
    Write-Host "[!] config.inc.php not found - theZoo-WebUI may need manual configuration" -ForegroundColor Yellow
}

# --- Accept theZoo EULA (create the conf file theZoo checks for) ---
$eulaConf = "$ZooRepo\conf\eula_run.conf"
$confDir = "$ZooRepo\conf"
if (-not (Test-Path $confDir)) {
    New-Item $confDir -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path $eulaConf)) {
    Set-Content $eulaConf "agreed" -Force
    Write-Host "[+] theZoo EULA acceptance created ($eulaConf)" -ForegroundColor Green
} else {
    Write-Host "[+] theZoo EULA already accepted" -ForegroundColor Green
}

# --- Create Scheduled Task for PHP built-in server ---
$taskName = "theZoo-WebUI"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($existingTask) {
    Write-Host "[*] Removing existing $taskName scheduled task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

# Find PHP executable path
$phpExe = (Get-Command php -ErrorAction SilentlyContinue).Source
if (-not $phpExe) {
    $phpExe = "C:\tools\php\php.exe"
}

Write-Host "[*] Creating scheduled task: $taskName (port $ZooPort)..." -ForegroundColor Yellow

$action = New-ScheduledTaskAction `
    -Execute $phpExe `
    -Argument "-S 0.0.0.0:$ZooPort -t `"$ZooRoot`"" `
    -WorkingDirectory $ZooRoot

$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -RestartCount 999 `
    -ExecutionTimeLimit (New-TimeSpan -Days 365) `
    -StartWhenAvailable

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "theZoo-WebUI PHP server on port $ZooPort" `
    -Force | Out-Null

# Start the task immediately
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3

# --- Add firewall rule ---
$fwRule = Get-NetFirewallRule -DisplayName "theZoo-WebUI" -ErrorAction SilentlyContinue
if (-not $fwRule) {
    New-NetFirewallRule -DisplayName "theZoo-WebUI" `
        -Direction Inbound -Protocol TCP -LocalPort $ZooPort `
        -Action Allow -Profile Any | Out-Null
    Write-Host "[+] Firewall rule added for port $ZooPort" -ForegroundColor Green
}

# --- Add Defender exclusion for theZoo directory (contains malware samples) ---
Write-Host "[*] Adding Defender exclusions for theZoo directories..." -ForegroundColor Yellow
Add-MpPreference -ExclusionPath $ZooRoot -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath $ZooRepo -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "$ZooRepo\malwares" -ErrorAction SilentlyContinue
Write-Host "[+] Defender exclusions added" -ForegroundColor Green

# --- Verify ---
Write-Host ""
Write-Host "=== theZoo Installation Complete ===" -ForegroundColor Cyan
Write-Host "  theZoo-WebUI: http://0.0.0.0:$ZooPort" -ForegroundColor White
Write-Host "  theZoo repo:  $ZooRepo" -ForegroundColor White
Write-Host "  PHP server:   Scheduled task '$taskName'" -ForegroundColor White
Write-Host ""

# Quick health check
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:$ZooPort" -UseBasicParsing -TimeoutSec 5
    Write-Host "[+] theZoo-WebUI responding: HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[!] theZoo-WebUI not responding yet (may need a moment to start)" -ForegroundColor Yellow
}
