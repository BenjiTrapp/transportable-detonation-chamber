<#
.SYNOPSIS
    Transportable Detonation Chamber - Build & Management Script (Windows)

.DESCRIPTION
    Cross-platform equivalent of the Makefile for Windows PowerShell.
    Manages the Vagrant VM lifecycle, deploys webui files, and interacts with services.

.EXAMPLE
    .\make.ps1 help
    .\make.ps1 install
    .\make.ps1 run
    .\make.ps1 up
    .\make.ps1 deploy
    .\make.ps1 deploy-restart
    .\make.ps1 submit -File .\sample.exe -Target both
#>

param(
    [Parameter(Position=0)]
    [ValidateSet(
        'help','prerequisites','install','run','run-debug','uninstall',
        'up','halt','destroy','reload','provision','provision-webui',
        'deploy','deploy-app','restart','deploy-restart','open','logs',
        'ssh','rdp','status','services','alerts','test','submit',
        'clean','clean-all'
    )]
    [string]$Target = 'help',

    [Parameter()]
    [string]$File,

    [Parameter()]
    [ValidateSet('agent','litterbox','both')]
    [string]$Target2 = 'both',

    [Parameter()]
    [Alias('IP')]
    [string]$VMIp = '172.17.251.7'
)

# --- Configuration ---
$ErrorActionPreference = 'Stop'
$VagrantFile = 'Vagrantfile'
$Provider = 'hyperv'
$WebuiUrl = "http://${VMIp}:9000"
$env:VAGRANT_VAGRANTFILE = $VagrantFile

# --- Helper: Get PS Remoting Session ---
function Get-VMSession {
    $pass = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('vagrant', $pass)
    New-PSSession -ComputerName $VMIp -Credential $cred
}

function Invoke-VM {
    param([scriptblock]$ScriptBlock)
    $pass = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('vagrant', $pass)
    Invoke-Command -ComputerName $VMIp -Credential $cred -ScriptBlock $ScriptBlock
}

# ============================================================================
# TARGETS
# ============================================================================

switch ($Target) {

    'help' {
        Write-Host ""
        Write-Host "  Transportable Detonation Chamber" -ForegroundColor Cyan
        Write-Host "  ================================"
        Write-Host "  Platform: windows  Provider: $Provider  VM: $VMIp"
        Write-Host ""
        Write-Host "  Setup:" -ForegroundColor Yellow
        Write-Host "    .\make.ps1 prerequisites   Check/install all prerequisites"
        Write-Host ""
        Write-Host "  Local (no VM required):" -ForegroundColor Yellow
        Write-Host "    .\make.ps1 install         Install Python venv + dependencies"
        Write-Host "    .\make.ps1 run             Run the Web UI locally (port 9000)"
        Write-Host "    .\make.ps1 run-debug       Run with auto-reload on file changes"
        Write-Host "    .\make.ps1 uninstall       Remove local venv"
        Write-Host ""
        Write-Host "  VM Lifecycle:" -ForegroundColor Yellow
        Write-Host "    .\make.ps1 up              Build and start the VM"
        Write-Host "    .\make.ps1 halt            Stop the VM gracefully"
        Write-Host "    .\make.ps1 destroy         Destroy the VM (irreversible)"
        Write-Host "    .\make.ps1 reload          Restart the VM (halt + up)"
        Write-Host "    .\make.ps1 provision       Re-run all provisioning scripts"
        Write-Host "    .\make.ps1 provision-webui Re-run webui provisioner only"
        Write-Host ""
        Write-Host "  Development (VM):" -ForegroundColor Yellow
        Write-Host "    .\make.ps1 deploy          Sync webui files (HTML/CSS/JS) to VM"
        Write-Host "    .\make.ps1 deploy-app      Sync Flask app.py backend to VM"
        Write-Host "    .\make.ps1 restart         Restart the Web UI service on VM"
        Write-Host "    .\make.ps1 deploy-restart  Deploy files then restart (combo)"
        Write-Host "    .\make.ps1 open            Open Web UI in browser"
        Write-Host "    .\make.ps1 logs            Show recent Web UI logs"
        Write-Host ""
        Write-Host "  Interaction:" -ForegroundColor Yellow
        Write-Host "    .\make.ps1 ssh             SSH into the VM"
        Write-Host "    .\make.ps1 rdp             Connect via RDP"
        Write-Host "    .\make.ps1 status          Show VM status + service health"
        Write-Host "    .\make.ps1 services        List all service states"
        Write-Host "    .\make.ps1 alerts          Show recent detection alerts"
        Write-Host "    .\make.ps1 test            Submit test sample to verify pipeline"
        Write-Host "    .\make.ps1 submit -File x  Submit a file for detonation"
        Write-Host ""
        Write-Host "  Cleanup:" -ForegroundColor Yellow
        Write-Host "    .\make.ps1 clean           Destroy VM + remove .vagrant"
        Write-Host "    .\make.ps1 clean-all       Also remove cached Vagrant boxes"
        Write-Host "    .\make.ps1 uninstall       Remove local venv"
        Write-Host ""
    }

    # --- Local Install ---

    'prerequisites' {
        Write-Host "[prerequisites] Checking system requirements..." -ForegroundColor Cyan
        $scriptPath = Join-Path $PSScriptRoot "scripts\check-prerequisites.ps1"
        if (Test-Path $scriptPath) {
            & $scriptPath
        } else {
            Write-Host "ERROR: scripts\check-prerequisites.ps1 not found" -ForegroundColor Red
        }
    }

    'install' {
        $VenvDir = "webui\.venv"
        Write-Host "[install] Setting up local development environment..." -ForegroundColor Cyan

        # Find Python - try multiple candidates (most specific first)
        $PythonExe = $null
        $candidates = @('python3.12', 'python3.11', 'python3.10', 'python3', 'python')
        foreach ($c in $candidates) {
            $cmd = Get-Command $c -ErrorAction SilentlyContinue
            if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
                # Skip Windows Store app execution aliases (they're ~0 byte stubs)
                $fileInfo = Get-Item $cmd.Source -ErrorAction SilentlyContinue
                if ($fileInfo -and $fileInfo.Length -lt 1024) {
                    # Could be a Store alias stub - try running it
                    try {
                        $ver = & $cmd.Source --version 2>$null
                        if ($LASTEXITCODE -eq 0 -and $ver -match 'Python 3\.\d+') {
                            $PythonExe = $cmd.Source
                            break
                        }
                    } catch { }
                } else {
                    # Real binary, verify version
                    try {
                        $ver = & $cmd.Source --version 2>$null
                        if ($LASTEXITCODE -eq 0 -and $ver -match 'Python 3\.\d+') {
                            $PythonExe = $cmd.Source
                            break
                        }
                    } catch { }
                }
            }
        }
        if (-not $PythonExe) {
            Write-Host "[install] ERROR: Python 3.10+ not found." -ForegroundColor Red
            Write-Host "  Install Python from https://python.org/downloads"
            Write-Host "  or via: winget install Python.Python.3.12"
            return
        }
        $pyVersion = & $PythonExe --version 2>$null
        Write-Host "[install] Found: $pyVersion ($PythonExe)"

        # Create venv
        if (-not (Test-Path "$VenvDir\Scripts\activate")) {
            Write-Host "[install] Creating virtual environment at $VenvDir..."
            & $PythonExe -m venv $VenvDir
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[install] ERROR: Failed to create venv." -ForegroundColor Red
                return
            }
        } else {
            Write-Host "[install] Virtual environment already exists."
        }

        # Install dependencies
        Write-Host "[install] Installing dependencies..."
        & "$VenvDir\Scripts\python.exe" -m pip install --upgrade pip -q 2>$null
        & "$VenvDir\Scripts\python.exe" -m pip install -r webui\requirements.txt -q
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[install] ERROR: pip install failed." -ForegroundColor Red
            return
        }

        # Show installed packages
        Write-Host ""
        Write-Host "[install] Installed packages:" -ForegroundColor Green
        & "$VenvDir\Scripts\python.exe" -m pip list --format=columns 2>$null | Select-Object -First 15
        Write-Host ""
        Write-Host "[install] Done! Run '.\make.ps1 run' to start the Web UI locally." -ForegroundColor Green
        Write-Host "  The UI will be at http://localhost:9000"
        Write-Host "  Note: Backend services (Rustinel, Fibratus, etc.) won't be available"
        Write-Host "  locally - the UI will show them as offline. Use '.\make.ps1 up' for full VM."
        Write-Host ""
    }

    'run' {
        $VenvDir = "webui\.venv"
        $PyExe = "$VenvDir\Scripts\python.exe"

        if (-not (Test-Path $PyExe)) {
            Write-Host "[run] ERROR: venv not found. Run '.\make.ps1 install' first." -ForegroundColor Red
            return
        }

        Write-Host ""
        Write-Host "[run] Starting Detonation Chamber Web UI" -ForegroundColor Cyan
        Write-Host "  URL:  http://localhost:9000"
        Write-Host "  Stop: Ctrl+C"
        Write-Host ""

        Push-Location webui
        try {
            & "..\$PyExe" app.py
        } finally {
            Pop-Location
        }
    }

    'run-debug' {
        $VenvDir = "webui\.venv"
        $PyExe = "$VenvDir\Scripts\python.exe"

        if (-not (Test-Path $PyExe)) {
            Write-Host "[run-debug] ERROR: venv not found. Run '.\make.ps1 install' first." -ForegroundColor Red
            return
        }

        Write-Host ""
        Write-Host "[run-debug] Starting in debug mode (auto-reload on changes)" -ForegroundColor Cyan
        Write-Host "  URL:  http://localhost:9000"
        Write-Host "  Stop: Ctrl+C"
        Write-Host ""

        $env:FLASK_DEBUG = "1"
        Push-Location webui
        try {
            & "..\$PyExe" app.py
        } finally {
            Pop-Location
            Remove-Item Env:\FLASK_DEBUG -ErrorAction SilentlyContinue
        }
    }

    'uninstall' {
        $VenvDir = "webui\.venv"
        if (Test-Path $VenvDir) {
            Write-Host "[uninstall] Removing virtual environment..." -ForegroundColor Yellow
            Remove-Item -Recurse -Force $VenvDir
            Write-Host "[uninstall] Done." -ForegroundColor Green
        } else {
            Write-Host "[uninstall] No venv found at $VenvDir" -ForegroundColor DarkGray
        }
    }

    # --- VM Lifecycle ---

    'up' {
        vagrant up --provider=$Provider
    }

    'halt' {
        vagrant halt
    }

    'destroy' {
        vagrant destroy -f
    }

    'reload' {
        vagrant reload
    }

    'provision' {
        vagrant provision
    }

    'provision-webui' {
        vagrant provision --provision-with webui,configure
    }

    # --- Development ---

    'deploy' {
        Write-Host "[deploy] Uploading webui files to VM at $VMIp..." -ForegroundColor Cyan
        $s = Get-VMSession
        try {
            Copy-Item 'webui\templates\index.html' -Destination 'C:\DetonationChamberUI\templates\index.html' -ToSession $s -Force
            Copy-Item 'webui\static\css\style.css' -Destination 'C:\DetonationChamberUI\static\css\style.css' -ToSession $s -Force
            Copy-Item 'webui\static\js\app.js' -Destination 'C:\DetonationChamberUI\static\js\app.js' -ToSession $s -Force
            Copy-Item 'webui\static\icon.png' -Destination 'C:\DetonationChamberUI\static\icon.png' -ToSession $s -Force -ErrorAction SilentlyContinue
            Write-Host "[deploy] Files synced successfully." -ForegroundColor Green
        } finally {
            Remove-PSSession $s
        }
    }

    'deploy-app' {
        Write-Host "[deploy-app] Uploading app.py..." -ForegroundColor Cyan
        $s = Get-VMSession
        try {
            Copy-Item 'webui\app.py' -Destination 'C:\DetonationChamberUI\app.py' -ToSession $s -Force
            Write-Host "[deploy-app] app.py synced." -ForegroundColor Green
        } finally {
            Remove-PSSession $s
        }
    }

    'restart' {
        Write-Host "[restart] Restarting Web UI..." -ForegroundColor Cyan
        Invoke-VM {
            Get-Process -Name python* -ErrorAction SilentlyContinue | Stop-Process -Force
            Start-Sleep -Seconds 2
            Start-ScheduledTask -TaskName 'DetonationChamberUI'
            Start-Sleep -Seconds 3
            $state = (Get-ScheduledTask -TaskName 'DetonationChamberUI').State
            Write-Host "Web UI: $state"
        }
    }

    'deploy-restart' {
        & $PSCommandPath deploy -VMIp $VMIp
        & $PSCommandPath restart -VMIp $VMIp
    }

    'open' {
        Start-Process $WebuiUrl
    }

    'logs' {
        Invoke-VM {
            if (Test-Path 'C:\DetonationChamberUI\webui.log') {
                Get-Content 'C:\DetonationChamberUI\webui.log' -Tail 50
            } else {
                Write-Host "No log file found. Task info:"
                Get-ScheduledTask -TaskName 'DetonationChamberUI' | Format-List State, LastRunTime, LastTaskResult
            }
        }
    }

    # --- Interaction ---

    'ssh' {
        vagrant ssh
    }

    'rdp' {
        vagrant rdp
    }

    'status' {
        Write-Host "`n--- Vagrant VM ---" -ForegroundColor Yellow
        vagrant status
        Write-Host "`n--- Web UI Health ---" -ForegroundColor Yellow
        try {
            $r = Invoke-WebRequest -Uri "$WebuiUrl/api/status" -UseBasicParsing -TimeoutSec 5
            Write-Host "Web UI (:9000): " -NoNewline
            Write-Host "ONLINE" -ForegroundColor Green
            $r.Content | ConvertFrom-Json | Format-List
        } catch {
            Write-Host "Web UI (:9000): " -NoNewline
            Write-Host "OFFLINE" -ForegroundColor Red
        }
    }

    'services' {
        Invoke-VM {
            Write-Host ""
            Write-Host "  SERVICE               STATE"
            Write-Host "  -------               -----"
            $tasks = @('DetonationChamberUI','Rustinel','DetonatorAgent','LitterBox','Fibratus','theZoo-WebUI')
            foreach ($t in $tasks) {
                $st = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
                if ($st) {
                    $color = if ($st.State -eq 'Running') { 'Green' } else { 'Red' }
                    Write-Host ("  " + $t.PadRight(22)) -NoNewline
                    Write-Host $st.State -ForegroundColor $color
                } else {
                    Write-Host ("  " + $t.PadRight(22)) -NoNewline
                    Write-Host "NOT FOUND" -ForegroundColor DarkGray
                }
            }
            # Check both Sysmon64 (x64) and Sysmon64a (ARM64) service names
            $sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
            if (-not $sysmon) { $sysmon = Get-Service Sysmon64a -ErrorAction SilentlyContinue }
            Write-Host ("  Sysmon".PadRight(24)) -NoNewline
            if ($sysmon -and $sysmon.Status -eq 'Running') {
                Write-Host $sysmon.Status -ForegroundColor Green
            } elseif ($sysmon) {
                Write-Host $sysmon.Status -ForegroundColor Red
            } else {
                Write-Host "NOT FOUND" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
    }

    'alerts' {
        try {
            $r = Invoke-WebRequest -Uri "$WebuiUrl/api/alerts" -UseBasicParsing -TimeoutSec 10
            $alerts = $r.Content | ConvertFrom-Json
            Write-Host "Total alerts: $($alerts.Count)" -ForegroundColor Cyan
            Write-Host ""
            $alerts | Select-Object -Last 10 | ForEach-Object {
                $sev = $_.severity
                $color = switch ($sev) { 'high' { 'Red' } 'critical' { 'DarkRed' } 'medium' { 'Yellow' } default { 'Gray' } }
                Write-Host "  $($_.timestamp) " -NoNewline
                Write-Host "[$sev]" -ForegroundColor $color -NoNewline
                Write-Host " $($_.rule_name)"
            }
        } catch {
            Write-Host "Failed to fetch alerts (is VM running?)" -ForegroundColor Red
        }
    }

    'test' {
        Write-Host "[test] Submitting test sample to pipeline..." -ForegroundColor Cyan
        $testFile = 'test_alerts\test_sample.txt'
        if (-not (Test-Path $testFile)) {
            New-Item -Path $testFile -Value 'MZ_test_payload_data' -Force | Out-Null
        }
        $boundary = "boundary$([Guid]::NewGuid().ToString('N').Substring(0,12))"
        $fileName = 'test_sample.exe'
        $fileBytes = [IO.File]::ReadAllBytes((Resolve-Path $testFile))
        $enc = [Text.Encoding]::GetEncoding('iso-8859-1')
        $nl = "`r`n"
        $body = "--$boundary${nl}Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"${nl}Content-Type: application/octet-stream${nl}${nl}$($enc.GetString($fileBytes))${nl}--$boundary--${nl}"
        try {
            $r = Invoke-WebRequest -Uri "$WebuiUrl/api/submit" -Method POST `
                -ContentType "multipart/form-data; boundary=$boundary" `
                -Body $body -UseBasicParsing -TimeoutSec 30
            Write-Host "[test] Response:" -ForegroundColor Green
            $r.Content | ConvertFrom-Json | Format-List
        } catch {
            Write-Host "[test] FAILED: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    'submit' {
        if (-not $File) {
            Write-Host "Usage: .\make.ps1 submit -File path\to\sample.exe [-Target2 agent|litterbox|both]" -ForegroundColor Yellow
            return
        }
        if (-not (Test-Path $File)) {
            Write-Host "File not found: $File" -ForegroundColor Red
            return
        }
        $boundary = "boundary$([Guid]::NewGuid().ToString('N').Substring(0,12))"
        $fileName = [IO.Path]::GetFileName($File)
        $fileBytes = [IO.File]::ReadAllBytes((Resolve-Path $File))
        $enc = [Text.Encoding]::GetEncoding('iso-8859-1')
        $nl = "`r`n"
        $body = "--$boundary${nl}Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"${nl}Content-Type: application/octet-stream${nl}${nl}$($enc.GetString($fileBytes))${nl}--$boundary${nl}Content-Disposition: form-data; name=`"target`"${nl}${nl}$Target2${nl}--$boundary--${nl}"
        try {
            $r = Invoke-WebRequest -Uri "$WebuiUrl/api/submit" -Method POST `
                -ContentType "multipart/form-data; boundary=$boundary" `
                -Body $body -UseBasicParsing -TimeoutSec 60
            Write-Host "Response:" -ForegroundColor Green
            $r.Content | ConvertFrom-Json | Format-List
        } catch {
            Write-Host "Submit failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # --- Cleanup ---

    'clean' {
        Write-Host "[clean] Destroying VM..." -ForegroundColor Yellow
        vagrant destroy -f 2>$null
        if (Test-Path .vagrant) {
            Remove-Item -Recurse -Force .vagrant
        }
        Write-Host "[clean] Done." -ForegroundColor Green
    }

    'clean-all' {
        & $PSCommandPath clean -VMIp $VMIp
        Write-Host "[clean-all] Removing cached boxes..." -ForegroundColor Yellow
        vagrant box remove gusztavvargadr/windows-11 --all --force 2>$null
        Write-Host "[clean-all] Done." -ForegroundColor Green
    }
}
