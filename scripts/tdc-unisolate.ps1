# tdc-unisolate.ps1
# The way out of ISOLATED mode when the Web UI cannot be reached.
#
# What it does, and only this:
#   1. sets DefaultOutboundAction to Allow on the Domain, Private and Public profiles
#   2. removes every firewall rule named TDC-FW-* (the blocks of the FIREWALL tab, the loopback allow
#      rule of ISOLATED mode and any per-fetch allow rule a fetch left behind)
#   3. says what it did
#
# It does not switch the firewall on or off, and it does not touch a rule of any other name.
# It sets Allow, the Windows default; the value ISOLATED remembered (webui\firewall_state.json) is
# not read here. If the VM was on Block before ISOLATED, put that back by hand:
#   Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
# The Web UI notices at its next start that the marker in firewall_state.json is stale and clears it.
#
# Run as Administrator.

$ErrorActionPreference = "Continue"
$failed = $false

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "=== TDC: leaving ISOLATED mode ===" -ForegroundColor Cyan

try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow -ErrorAction Stop
    Write-Host "[+] DefaultOutboundAction is now Allow on Domain, Private and Public" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not set DefaultOutboundAction: $($_.Exception.Message)" -ForegroundColor Red
    $failed = $true
}

$rules = @(Get-NetFirewallRule -DisplayName "TDC-FW-*" -ErrorAction SilentlyContinue)
foreach ($rule in $rules) {
    try {
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
        Write-Host "[+] Removed rule $($rule.DisplayName)" -ForegroundColor Green
    } catch {
        Write-Host "[!] Could not remove rule $($rule.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
        $failed = $true
    }
}
if ($rules.Count -eq 0) {
    Write-Host "[*] No TDC-FW-* rules found" -ForegroundColor Gray
}

$profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
foreach ($p in $profiles) {
    Write-Host ("[*] {0}: firewall {1}, outbound {2}" -f $p.Name, $(if ($p.Enabled -eq 'True') { 'on' } else { 'OFF' }), $p.DefaultOutboundAction)
}

if ($failed) {
    Write-Host "=== Not everything worked; see above ===" -ForegroundColor Yellow
    exit 1
}
Write-Host "=== Done ===" -ForegroundColor Cyan
exit 0
