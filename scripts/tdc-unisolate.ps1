# tdc-unisolate.ps1
# The way out of ISOLATED mode when the Web UI cannot be reached.
#
# What it does, and only this:
#   1. opens the default outbound action of the Domain, Private and Public profiles: each goes back to the
#      value ISOLATED recorded (outbound_before in firewall_state.json) when that is Allow or NotConfigured, so the
#      firewall is configured as it was found, and to Allow otherwise
#   2. switches on again the outbound Allow rules of Windows' own that ISOLATED switched off (Core Networking's
#      DNS among them): exactly the names recorded in allow_disabled of the web UI's firewall_state.json, and only
#      outbound Allow rules of this machine (the PersistentStore)
#   3. removes every firewall rule named TDC-FW-* (the blocks of the FIREWALL tab, any per-fetch allow
#      rule a fetch left behind, and the loopback allow rule older versions of ISOLATED wrote)
#   4. says what it did
#
# It does not switch the firewall on or off, and it touches no other rule.
# It never puts back Block: it is the way out. If the VM was on Block before ISOLATED, it says so, and that is
# put back by hand:
#   Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public -DefaultOutboundAction Block
# The file is only read, never written: the Web UI notices at its next start that the marker in it is stale,
# switches the recorded rules on again (which changes nothing they already are) and clears it.
#
# Run as Administrator.

param(
    [string]$StateFile = "C:\DetonationChamberUI\firewall_state.json"
)

$ErrorActionPreference = "Continue"
$failed = $false

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "=== TDC: leaving ISOLATED mode ===" -ForegroundColor Cyan

$recorded = @()
$stateRead = $false
if (Test-Path -LiteralPath $StateFile) {
    try {
        $state = Get-Content -LiteralPath $StateFile -Raw -ErrorAction Stop | ConvertFrom-Json
        $recorded = @($state.allow_disabled | Where-Object { $_ -is [string] -and $_ -and -not $_.StartsWith('TDC-FW-') })
        $stateRead = $true
    } catch {
        Write-Host "[!] Could not read $StateFile ($($_.Exception.Message)): the Windows rules ISOLATED switched off stay off." -ForegroundColor Red
        $failed = $true
    }
} else {
    Write-Host "[*] No $($StateFile): no Windows rule recorded as switched off by ISOLATED" -ForegroundColor Gray
    $stateRead = $true
}
# What was configured before ISOLATED, per profile (outbound_before: "Allow", "NotConfigured", "Block", or
# "Domain=...,Private=...,Public=..."). Only an opening value is put back; Block, or nothing readable, becomes Allow.
$profileNames = @('Domain', 'Private', 'Public')
$before = @{}
$text = if ($state -and $state.outbound_before -is [string]) { $state.outbound_before.Trim() } else { '' }
if ($text -in @('Allow', 'NotConfigured', 'Block')) {
    foreach ($n in $profileNames) { $before[$n] = $text }
} elseif ($text) {
    foreach ($part in $text.Split(',')) {
        $kv = $part.Split('=')
        if ($kv.Count -eq 2 -and $profileNames -contains $kv[0].Trim() -and @('Allow', 'NotConfigured', 'Block') -contains $kv[1].Trim()) {
            $before[$kv[0].Trim()] = $kv[1].Trim()
        }
    }
}
foreach ($n in $profileNames) {
    $value = if ($before[$n] -in @('Allow', 'NotConfigured')) { $before[$n] } else { 'Allow' }
    try {
        Set-NetFirewallProfile -PolicyStore PersistentStore -Profile $n -DefaultOutboundAction $value -ErrorAction Stop
        Write-Host "[+] $($n): DefaultOutboundAction is now $value" -ForegroundColor Green
        if ($before[$n] -eq 'Block') {
            Write-Host "    It was Block before ISOLATED; put that back by hand if it is wanted." -ForegroundColor Yellow
        } elseif (-not $before[$n]) {
            Write-Host "    No recorded value before ISOLATED; Allow, the Windows default, was used." -ForegroundColor Gray
        }
    } catch {
        Write-Host "[!] $($n): could not set DefaultOutboundAction: $($_.Exception.Message)" -ForegroundColor Red
        $failed = $true
    }
}

if (-not $stateRead) {
    Write-Host "    The ones that are off now:  Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled False" -ForegroundColor Yellow
}
if ($recorded.Count -gt 0) {
    $want = @{}
    foreach ($n in $recorded) { $want[$n] = $true }
    $found = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object {
        $want.ContainsKey([string]$_.Name) -and [string]$_.Direction -eq 'Outbound' -and [string]$_.Action -eq 'Allow'
    })
    foreach ($rule in $found) {
        try {
            $rule | Enable-NetFirewallRule -ErrorAction Stop
            Write-Host "[+] Switched on again: $($rule.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Host "[!] Could not switch on $($rule.DisplayName) ($($rule.Name)): $($_.Exception.Message)" -ForegroundColor Red
            $failed = $true
        }
    }
    $gone = $recorded.Count - $found.Count
    if ($gone -gt 0) {
        Write-Host "[*] $gone recorded rule(s) no longer exist; nothing to switch on for them" -ForegroundColor Gray
    }
} elseif ($stateRead) {
    Write-Host "[*] No Windows rule to switch on again" -ForegroundColor Gray
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
