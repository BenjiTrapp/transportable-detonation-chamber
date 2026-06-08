# install-prerequisites.ps1
# Installs .NET 8.0 SDK, Python 3.12, Git, and other prerequisites
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Prerequisites ===" -ForegroundColor Cyan

# --- Install Chocolatey (package manager) ---
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Installing Chocolatey..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    $env:Path = "$env:ProgramData\chocolatey\bin;$env:Path"
    refreshenv
} else {
    Write-Host "[+] Chocolatey already installed" -ForegroundColor Green
}

# --- Install Git ---
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Installing Git..." -ForegroundColor Yellow
    choco install git -y --no-progress
    $env:Path = "C:\Program Files\Git\bin;$env:Path"
} else {
    Write-Host "[+] Git already installed" -ForegroundColor Green
}

# --- Install .NET 8.0 SDK ---
$dotnetVersion = "8.0"
$dotnetInstalled = $false
if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    $sdks = dotnet --list-sdks 2>$null
    if ($sdks -match "8\.0") {
        $dotnetInstalled = $true
    }
}
if (-not $dotnetInstalled) {
    Write-Host "[*] Installing .NET 8.0 SDK..." -ForegroundColor Yellow
    choco install dotnet-8.0-sdk -y --no-progress
    $env:Path = "C:\Program Files\dotnet;$env:Path"
} else {
    Write-Host "[+] .NET 8.0 SDK already installed" -ForegroundColor Green
}

# --- Install Python 3.12 ---
# Note: Windows 11 has a stub python.exe that redirects to Microsoft Store.
# We must check if a *real* Python is installed, not just the stub.
$pythonReady = $false
try {
    $pyVer = python --version 2>&1
    if ($pyVer -match "Python 3\.\d+") {
        $pythonReady = $true
        Write-Host "[+] Python already installed: $pyVer" -ForegroundColor Green
    }
} catch {}

if (-not $pythonReady) {
    Write-Host "[*] Installing Python 3.12 via Chocolatey..." -ForegroundColor Yellow
    # Disable the Windows Store alias stubs first
    $aliasDir = "$env:LOCALAPPDATA\Microsoft\WindowsApps"
    Remove-Item "$aliasDir\python.exe" -Force -ErrorAction SilentlyContinue
    Remove-Item "$aliasDir\python3.exe" -Force -ErrorAction SilentlyContinue

    choco install python312 -y --no-progress
    # Refresh PATH
    $env:Path = "C:\Python312;C:\Python312\Scripts;$env:Path"
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -notlike "*Python312*") {
        [System.Environment]::SetEnvironmentVariable("Path", "C:\Python312;C:\Python312\Scripts;$machinePath", "Machine")
    }
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# --- Install pip packages needed for Detonator ---
Write-Host "[*] Upgrading pip and installing uv..." -ForegroundColor Yellow
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    # Try common paths
    $pythonExe = "C:\Python312\python.exe"
}
if (Test-Path $pythonExe) {
    & $pythonExe -m pip install --upgrade pip --quiet 2>$null
    & $pythonExe -m pip install uv --quiet 2>$null
    Write-Host "[+] pip and uv installed" -ForegroundColor Green
} else {
    Write-Host "[!] Python not found at expected path - pip/uv installation skipped" -ForegroundColor Yellow
}

# --- Install 7-Zip for archive extraction ---
if (-not (Get-Command 7z -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Installing 7-Zip..." -ForegroundColor Yellow
    choco install 7zip -y --no-progress
}

# --- Disable Windows Defender Real-Time Protection ---
# Required so malware samples can actually execute during detonation
Write-Host "[*] Configuring Windows Defender exclusions..." -ForegroundColor Yellow
$detonationPaths = @(
    "C:\Users\Public\Downloads",
    "C:\tools",
    "C:\detonator",
    "C:\DetonatorAgent",
    "C:\LitterBox"
)
foreach ($path in $detonationPaths) {
    Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
}

# Create tools directory
if (-not (Test-Path "C:\tools")) {
    New-Item -ItemType Directory -Path "C:\tools" -Force | Out-Null
}

# --- Configure Windows Firewall ---
Write-Host "[*] Configuring firewall rules..." -ForegroundColor Yellow
# Allow DetonatorAgent API
New-NetFirewallRule -DisplayName "DetonatorAgent API" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
# Allow Detonator Web UI
New-NetFirewallRule -DisplayName "Detonator Web UI" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
# Allow Detonator REST API
New-NetFirewallRule -DisplayName "Detonator REST API" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null

# --- Enable OpenSSH Server ---
Write-Host "[*] Installing OpenSSH Server..." -ForegroundColor Yellow
$sshCapability = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"
if ($sshCapability.State -ne "Installed") {
    Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0" -ErrorAction SilentlyContinue
    Start-Service sshd -ErrorAction SilentlyContinue
    Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
}

Write-Host "[+] Prerequisites installation complete!" -ForegroundColor Green
