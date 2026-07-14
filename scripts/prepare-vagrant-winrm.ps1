# prepare-vagrant-winrm.ps1
# One-time bootstrap for a Windows 11 ARM64 VM that was installed MANUALLY
# (e.g. in UTM) without the Autounattend.xml from build-box-macos.sh.
#
# Run this INSIDE the VM, from an ELEVATED PowerShell (Run as Administrator):
#
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\prepare-vagrant-winrm.ps1
#
# It reproduces exactly what the unattended install would have configured:
#   - a local 'vagrant' administrator account (password: vagrant)
#   - WinRM over HTTP (5985), plaintext + basic auth  -> Vagrant communicator
#   - RDP enabled
#   - firewall opened for WinRM/RDP
#   - LocalAccountTokenFilterPolicy so the local account has full remote admin
#
# After it finishes, the host can reach the VM and the detonation-chamber
# provisioning scripts can run.

$ErrorActionPreference = 'Stop'

function Say($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)  { Write-Host "[+] $m" -ForegroundColor Green }

# --- 0. Elevation check ------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run from an elevated (Administrator) PowerShell."
}

# --- 1. vagrant user ---------------------------------------------------------
Say "Creating local 'vagrant' administrator account..."
$pw = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
if (Get-LocalUser -Name 'vagrant' -ErrorAction SilentlyContinue) {
    Set-LocalUser -Name 'vagrant' -Password $pw
    Ok "vagrant user already existed - password reset."
} else {
    New-LocalUser -Name 'vagrant' -Password $pw -FullName 'vagrant' `
        -Description 'Vagrant' -PasswordNeverExpires
    Ok "vagrant user created."
}
Add-LocalGroupMember -Group 'Administrators' -Member 'vagrant' -ErrorAction SilentlyContinue
# Also add to the localized Administrators group if present (de-DE: 'Administratoren')
Add-LocalGroupMember -Group 'Administratoren' -Member 'vagrant' -ErrorAction SilentlyContinue
Ok "vagrant added to Administrators."

# --- 2. Allow local account full remote admin --------------------------------
Say "Setting LocalAccountTokenFilterPolicy..."
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord -Force
Ok "Done."

# --- 3. WinRM ----------------------------------------------------------------
Say "Configuring WinRM (HTTP/5985, plaintext + basic auth)..."
Enable-PSRemoting -Force -SkipNetworkProfileCheck
winrm quickconfig -quiet -force 2>$null
winrm set winrm/config/service        '@{AllowUnencrypted="true"}'  | Out-Null
winrm set winrm/config/service/auth   '@{Basic="true"}'            | Out-Null
winrm set winrm/config/client         '@{AllowUnencrypted="true"}' | Out-Null
winrm set winrm/config/client/auth    '@{Basic="true"}'            | Out-Null
winrm set winrm/config                '@{MaxTimeoutms="1800000"}'  | Out-Null
Set-Service -Name WinRM -StartupType Automatic
Start-Service WinRM
Ok "WinRM configured and running."

# --- 4. Network profile -> Private (WinRM refuses Public by default) ----------
Say "Setting network connection profile to Private..."
Get-NetConnectionProfile | ForEach-Object {
    Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex `
        -NetworkCategory Private -ErrorAction SilentlyContinue
}
Ok "Done."

# --- 5. RDP ------------------------------------------------------------------
Say "Enabling Remote Desktop..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' -Value 0 -Force
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
Enable-NetFirewallRule -DisplayGroup 'Remotedesktop'  -ErrorAction SilentlyContinue
Ok "RDP enabled."

# --- 6. Firewall for WinRM ---------------------------------------------------
Say "Opening firewall for WinRM (5985)..."
New-NetFirewallRule -DisplayName 'WinRM-HTTP-In' -Name 'WinRM-HTTP-In' `
    -Protocol TCP -LocalPort 5985 -Action Allow -Direction Inbound `
    -ErrorAction SilentlyContinue | Out-Null
Ok "Firewall rule added."

# --- 7. Report ---------------------------------------------------------------
Write-Host ""
Ok "VM is now prepared for Vagrant/WinRM."
Write-Host ""
Write-Host "  Verify the VM's IP address with:  ipconfig" -ForegroundColor Yellow
Write-Host "  From the Mac host, test with:" -ForegroundColor Yellow
Write-Host "    Test-NetConnection <vm-ip> -Port 5985" -ForegroundColor Yellow
Write-Host ""
