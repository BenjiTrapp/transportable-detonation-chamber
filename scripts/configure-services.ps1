# configure-services.ps1
# Configures and starts all services in the detonation chamber
# This script runs on every 'vagrant up' (run: "always")
#
# Services started:
#   1. Fibratus (kernel ETW telemetry + detection rules) - Windows Service
#   2. Rustinel (ETW + Sigma/YARA/IOC detection) - Scheduled Task
#   3. DetonatorAgent (file execution + EDR log collection API on :8080) - Scheduled Task
#   4. Detonator API (FastAPI on :8000) + UI (Flask on :5000) - Scheduled Tasks
#   5. LitterBox (payload analysis sandbox on :1337) - Scheduled Task
#   6. Detonation Chamber UI (unified web UI on :9000) - Scheduled Task
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Configuring and Starting Services ===" -ForegroundColor Cyan

$detonatorDir = "C:\detonator"
$detonatorAgentDir = "C:\DetonatorAgent"
$rustinelDir = "C:\tools\rustinel"
$litterboxDir = "C:\LitterBox"
$fibratusDir = "$env:ProgramFiles\Fibratus"
$webuiDir = "C:\DetonationChamberUI"
$logsDir = "C:\tools\logs"

# Create logs directory
New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

# --- Helper: Register and start a scheduled task for a background service ---
function Register-ServiceTask {
    param(
        [string]$Name,
        [string]$Command,
        [string]$Arguments = "",
        [string]$WorkingDirectory = ""
    )

    # Remove existing task
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue

    # Create a CMD wrapper that redirects output to log
    $wrapperPath = "$logsDir\run-${Name}.cmd"
    $logPath = "$logsDir\${Name}.log"

    if ($Arguments) {
        $cmdContent = "@echo off & cd /d `"$WorkingDirectory`" & `"$Command`" $Arguments > `"$logPath`" 2>&1"
    } else {
        $cmdContent = "@echo off & cd /d `"$WorkingDirectory`" & `"$Command`" > `"$logPath`" 2>&1"
    }
    Set-Content -Path $wrapperPath -Value $cmdContent

    # Create and register the task
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$wrapperPath`"" -WorkingDirectory $WorkingDirectory
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
    Start-ScheduledTask -TaskName $Name

    Write-Host "[+] $Name registered and started" -ForegroundColor Green
}

# --- Firewall Rules ---
Write-Host "`n--- Configuring Firewall ---" -ForegroundColor Cyan
# Remove old rules and create consolidated one
Get-NetFirewallRule -DisplayName "Detonation Chamber*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Detonation Chamber - All Services" -Direction Inbound -LocalPort 5000,8000,8080,9000,1337 -Protocol TCP -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# Program-level rule for Python processes
New-NetFirewallRule -DisplayName "Detonation Chamber - Python" -Direction Inbound -Program "C:\DetonationChamberUI\venv\Scripts\python.exe" -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Detonation Chamber - Python (Detonator)" -Direction Inbound -Program "C:\detonator\.venv\Scripts\python.exe" -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Detonation Chamber - Python (LitterBox)" -Direction Inbound -Program "C:\LitterBox\venv\Scripts\python.exe" -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] Firewall rules configured for ports 5000, 8000, 8080, 9000, 1337" -ForegroundColor Green

# --- Sample / Infected folder ---
Write-Host "`n--- Sample Directories ---" -ForegroundColor Cyan
$infectedDir = "C:\Users\vagrant\Desktop\infected"
New-Item -ItemType Directory -Path $infectedDir -Force | Out-Null
New-Item -ItemType Directory -Path "C:\samples" -Force | Out-Null
# Exclude sample directories from Windows Defender so malware samples aren't quarantined
Add-MpPreference -ExclusionPath $infectedDir -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\samples" -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\Users\Public\Downloads" -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\LitterBox" -ErrorAction SilentlyContinue
Write-Host "[+] Sample directories created and excluded from Defender" -ForegroundColor Green
Write-Host "    Desktop\infected: $infectedDir" -ForegroundColor Gray
Write-Host "    Samples:          C:\samples" -ForegroundColor Gray
Write-Host "    Agent drop dir:   C:\Users\Public\Downloads" -ForegroundColor Gray
Write-Host "    LitterBox:        C:\LitterBox" -ForegroundColor Gray

# --- 1. Start Fibratus ---
Write-Host "`n--- Fibratus ---" -ForegroundColor Cyan
$fibratusExe = "$fibratusDir\Bin\fibratus.exe"
if (-not (Test-Path $fibratusExe)) {
    $fibratusExe = "$fibratusDir\fibratus.exe"
}

if (Test-Path $fibratusExe) {
    # Apply latest config if available
    if (Test-Path "C:\vagrant_config\fibratus.yml") {
        $fibratusConfigDest = "$fibratusDir\Config\fibratus.yml"
        if (Test-Path (Split-Path $fibratusConfigDest -Parent)) {
            Copy-Item "C:\vagrant_config\fibratus.yml" $fibratusConfigDest -Force
        }
    }

    # Fibratus runs as a Windows Service (installed by install-fibratus.ps1)
    $fibratusSvc = Get-Service -Name "fibratus" -ErrorAction SilentlyContinue
    if ($fibratusSvc) {
        if ($fibratusSvc.Status -ne "Running") {
            Start-Service -Name "fibratus" -ErrorAction SilentlyContinue
        }
        if ((Get-Service "fibratus" -ErrorAction SilentlyContinue).Status -eq "Running") {
            Write-Host "[+] Fibratus service running" -ForegroundColor Green
        } else {
            Write-Host "[!] Fibratus service failed to start - check config" -ForegroundColor Yellow
        }
    } else {
        # Install service if not present
        & $fibratusExe install-service 2>$null
        Set-Service -Name "fibratus" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "fibratus" -ErrorAction SilentlyContinue
        Write-Host "[+] Fibratus service installed and started" -ForegroundColor Green
    }
} else {
    Write-Host "[!] Fibratus not found - skipping" -ForegroundColor Yellow
}

# --- 2. Start Rustinel ---
Write-Host "`n--- Rustinel ---" -ForegroundColor Cyan
$rustinelExe = "$rustinelDir\rustinel.exe"
if (Test-Path $rustinelExe) {
    # Apply latest config if available
    if (Test-Path "C:\vagrant_config\rustinel-config.toml") {
        Copy-Item "C:\vagrant_config\rustinel-config.toml" "$rustinelDir\config.toml" -Force
    }

    # Rustinel needs a PowerShell wrapper (CMD pipe redirection causes early exit)
    Unregister-ScheduledTask -TaskName "Rustinel" -Confirm:$false -ErrorAction SilentlyContinue
    $ps1Content = @"
Start-Process -FilePath "$rustinelExe" -ArgumentList "run" -WorkingDirectory "$rustinelDir" -WindowStyle Hidden -RedirectStandardOutput "$logsDir\Rustinel-stdout.log" -RedirectStandardError "$logsDir\Rustinel-stderr.log" -Wait
"@
    Set-Content -Path "$logsDir\run-Rustinel.ps1" -Value $ps1Content
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File $logsDir\run-Rustinel.ps1" -WorkingDirectory $rustinelDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "Rustinel" -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
    Start-ScheduledTask -TaskName "Rustinel"
    Start-Sleep -Seconds 3
    Write-Host "[+] Rustinel registered and started" -ForegroundColor Green
} else {
    Write-Host "[!] Rustinel not found at $rustinelExe - skipping" -ForegroundColor Yellow
}

# --- 3. Start DetonatorAgent ---
Write-Host "`n--- DetonatorAgent ---" -ForegroundColor Cyan
$agentExe = "$detonatorAgentDir\publish\DetonatorAgent.exe"
$agentDll = "$detonatorAgentDir\publish\DetonatorAgent.dll"

if (Test-Path $agentExe) {
    Register-ServiceTask -Name "DetonatorAgent" -Command $agentExe -Arguments "--port 8080 --edr fibratus" -WorkingDirectory "$detonatorAgentDir\publish"
    Start-Sleep -Seconds 3
} elseif (Test-Path $agentDll) {
    $dotnetExe = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
    if ($dotnetExe) {
        Register-ServiceTask -Name "DetonatorAgent" -Command $dotnetExe -Arguments "$agentDll --port 8080 --edr fibratus" -WorkingDirectory "$detonatorAgentDir\publish"
        Start-Sleep -Seconds 3
    }
} elseif (Test-Path "$detonatorAgentDir\DetonatorAgent.csproj") {
    $dotnetExe = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
    if ($dotnetExe) {
        Register-ServiceTask -Name "DetonatorAgent" -Command $dotnetExe -Arguments "run -- --port 8080 --edr fibratus" -WorkingDirectory $detonatorAgentDir
        Start-Sleep -Seconds 5
    }
} else {
    Write-Host "[!] DetonatorAgent not found - skipping" -ForegroundColor Yellow
}

# Verify DetonatorAgent is responding
Start-Sleep -Seconds 2
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8080/api/lock/status" -UseBasicParsing -TimeoutSec 5
    Write-Host "[+] DetonatorAgent API responding: $($response.Content)" -ForegroundColor Green
} catch {
    Write-Host "[!] DetonatorAgent API not yet responding (may need more time)" -ForegroundColor Yellow
}

# --- 4. Start Detonator (API + UI) ---
Write-Host "`n--- Detonator (API + UI) ---" -ForegroundColor Cyan
$venvPython = "$detonatorDir\.venv\Scripts\python.exe"

if (Test-Path $venvPython) {
    # Apply latest profiles config
    if (Test-Path "C:\vagrant_config\profiles_init.yaml") {
        Copy-Item "C:\vagrant_config\profiles_init.yaml" "$detonatorDir\profiles_init.yaml" -Force
    }

    # Detonator API (FastAPI/uvicorn on port 8000)
    # Build the Python command as a single argument string for cmd wrapper
    $apiCmd = "-c `"from detonatorapi.fastapi_app import app; import uvicorn; uvicorn.run(app, host='0.0.0.0', port=8000)`""
    Register-ServiceTask -Name "DetonatorAPI" -Command $venvPython -Arguments $apiCmd -WorkingDirectory $detonatorDir
    Start-Sleep -Seconds 3

    # Detonator UI (Flask on port 5000)
    Register-ServiceTask -Name "DetonatorUI" -Command $venvPython -Arguments "-m detonatorui" -WorkingDirectory $detonatorDir
    Start-Sleep -Seconds 3

    Write-Host "    API: http://localhost:8000" -ForegroundColor Gray
    Write-Host "    UI:  http://localhost:5000" -ForegroundColor Gray
} else {
    Write-Host "[!] Detonator Python venv not found - skipping" -ForegroundColor Yellow
}

# --- 5. Start LitterBox ---
Write-Host "`n--- LitterBox ---" -ForegroundColor Cyan
$litterboxPython = "$litterboxDir\venv\Scripts\python.exe"

if (Test-Path $litterboxPython) {
    # Apply latest config if available
    if (Test-Path "C:\vagrant_config\litterbox-config.yaml") {
        Copy-Item "C:\vagrant_config\litterbox-config.yaml" "$litterboxDir\Config\config.yaml" -Force
    }

    Register-ServiceTask -Name "LitterBox" -Command $litterboxPython -Arguments "litterbox.py" -WorkingDirectory $litterboxDir
    Start-Sleep -Seconds 3

    Write-Host "    URL: http://localhost:1337" -ForegroundColor Gray
} else {
    Write-Host "[!] LitterBox Python venv not found - skipping" -ForegroundColor Yellow
}

# --- 6. Start Detonation Chamber UI ---
Write-Host "`n--- Detonation Chamber UI ---" -ForegroundColor Cyan
$webuiPython = "$webuiDir\venv\Scripts\python.exe"

if (Test-Path $webuiPython) {
    Register-ServiceTask -Name "DetonationChamberUI" -Command $webuiPython -Arguments "app.py" -WorkingDirectory $webuiDir
    Start-Sleep -Seconds 3

    Write-Host "    URL: http://localhost:9000" -ForegroundColor Gray
} else {
    Write-Host "[!] Web UI Python venv not found - skipping" -ForegroundColor Yellow
}

# --- Summary ---
Write-Host "`n" -NoNewline
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Detonation Chamber - Service Status" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Wait a moment for all services to fully start
Start-Sleep -Seconds 5

Write-Host "  Fibratus:        " -NoNewline
$fibratusSvc = Get-Service -Name "fibratus" -ErrorAction SilentlyContinue
if ($fibratusSvc -and $fibratusSvc.Status -eq "Running") {
    Write-Host "RUNNING (service)" -ForegroundColor Green
} else {
    Write-Host "NOT RUNNING" -ForegroundColor Red
}

Write-Host "  Rustinel:        " -NoNewline
$rustTask = Get-ScheduledTask -TaskName "Rustinel" -ErrorAction SilentlyContinue
if ($rustTask -and $rustTask.State -eq "Running") {
    Write-Host "RUNNING (task)" -ForegroundColor Green
} else {
    Write-Host "NOT RUNNING (ETW may require elevation)" -ForegroundColor Yellow
}

Write-Host "  DetonatorAgent:  " -NoNewline
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:8080/api/lock/status" -UseBasicParsing -TimeoutSec 3
    Write-Host "RUNNING (port 8080)" -ForegroundColor Green
} catch {
    Write-Host "NOT RUNNING" -ForegroundColor Red
}

Write-Host "  Detonator API:   " -NoNewline
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:8000" -UseBasicParsing -TimeoutSec 3
    Write-Host "RUNNING (port 8000)" -ForegroundColor Green
} catch {
    Write-Host "NOT RUNNING" -ForegroundColor Yellow
}

Write-Host "  Detonator UI:    " -NoNewline
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:5000" -UseBasicParsing -TimeoutSec 3
    Write-Host "RUNNING (port 5000)" -ForegroundColor Green
} catch {
    Write-Host "NOT RUNNING" -ForegroundColor Yellow
}

Write-Host "  LitterBox:       " -NoNewline
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:1337" -UseBasicParsing -TimeoutSec 3
    Write-Host "RUNNING (port 1337)" -ForegroundColor Green
} catch {
    Write-Host "NOT RUNNING" -ForegroundColor Yellow
}

Write-Host "  Unified UI:      " -NoNewline
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:9000" -UseBasicParsing -TimeoutSec 3
    Write-Host "RUNNING (port 9000)" -ForegroundColor Green
} catch {
    Write-Host "NOT RUNNING" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Logs: $logsDir" -ForegroundColor Gray
Write-Host "  >> OPEN: http://localhost:9000 <<" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
