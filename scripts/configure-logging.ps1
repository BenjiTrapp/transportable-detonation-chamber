# configure-logging.ps1
# Turns on the Windows logs the LOGS tab of the web UI reads:
#   1. PowerShell Script Block Logging and Module Logging (Event IDs 4104 / 4103)
#   2. A 256 MB PowerShell operational log
#   3. Windows Firewall logging of allowed and blocked packets (pfirewall.log)
#   4. The BITS client operational log, 32 MB (the FIREWALL tab reads download URLs from it)
#
# Safe to run any number of times (runs on every 'vagrant up'). Run as Administrator.

$ErrorActionPreference = "Continue"

Write-Host "=== Configuring logging for the LOGS tab ===" -ForegroundColor Cyan

function Set-PolicyValue {
    param([string]$Path, [string]$Name, $Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

$psPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

# --- PowerShell Script Block Logging ---
try {
    Set-PolicyValue -Path "$psPolicy\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    Write-Host "[+] Script Block Logging enabled" -ForegroundColor Green
} catch {
    Write-Host "[!] Script Block Logging: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- PowerShell Module Logging (all modules) ---
try {
    Set-PolicyValue -Path "$psPolicy\ModuleLogging" -Name "EnableModuleLogging" -Value 1
    $moduleNames = "$psPolicy\ModuleLogging\ModuleNames"
    if (-not (Test-Path $moduleNames)) { New-Item -Path $moduleNames -Force | Out-Null }
    New-ItemProperty -Path $moduleNames -Name "*" -Value "*" -PropertyType String -Force | Out-Null
    Write-Host "[+] Module Logging enabled for all modules" -ForegroundColor Green
} catch {
    Write-Host "[!] Module Logging: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- PowerShell operational log: 256 MB ---
try {
    wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:268435456
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] PowerShell operational log limited to 256 MB" -ForegroundColor Green
    } else {
        Write-Host "[!] wevtutil exited with code $LASTEXITCODE" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] PowerShell operational log: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- Windows Firewall log ---
try {
    $firewallLog = "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
    Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767 -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
    Write-Host "[+] Firewall logs allowed and blocked packets to $firewallLog" -ForegroundColor Green
    $off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
    if ($off.Count -gt 0) {
        Write-Host "[!] Firewall is off for: $(($off | ForEach-Object { $_.Name }) -join ', '); those profiles log no packets" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Firewall logging: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- BITS client log: on, 32 MB (the FIREWALL tab reads the URLs of BITS jobs from it) ---
try {
    wevtutil sl Microsoft-Windows-Bits-Client/Operational /e:true /ms:33554432
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] BITS client log enabled and limited to 32 MB" -ForegroundColor Green
    } else {
        Write-Host "[!] wevtutil exited with code $LASTEXITCODE" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] BITS client log: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "=== Logging configured ===" -ForegroundColor Cyan
exit 0
