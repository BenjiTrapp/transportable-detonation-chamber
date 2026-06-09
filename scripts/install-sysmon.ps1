# install-sysmon.ps1
# Installs Sysmon (System Monitor) from Sysinternals with comprehensive logging config
#
# Sysmon provides:
#   - Process creation/termination with full command lines
#   - Network connection logging
#   - File creation time changes
#   - Driver/image loading
#   - Raw access read (disk)
#   - Registry modifications
#   - DNS query logging
#   - Pipe/WMI event monitoring
#   - Clipboard capture
#
# Uses SwiftOnSecurity/sysmon-config for tuned event filtering
# Events logged to: Microsoft-Windows-Sysmon/Operational
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Sysmon ===" -ForegroundColor Cyan

# Detect architecture - ARM64 uses Sysmon64a.exe, x86_64 uses Sysmon64.exe
$isArm64 = ($env:PROCESSOR_ARCHITECTURE -eq "ARM64")
$sysmonDir = "C:\tools\sysmon"
if ($isArm64) {
    $sysmonExe = "$sysmonDir\Sysmon64a.exe"
    $sysmonServiceName = "Sysmon64a"
    Write-Host "[*] ARM64 detected - will use Sysmon64a.exe (native ARM64 build)" -ForegroundColor Yellow
} else {
    $sysmonExe = "$sysmonDir\Sysmon64.exe"
    $sysmonServiceName = "Sysmon64"
}
$configPath = "$sysmonDir\sysmonconfig.xml"

# Check if already installed and running
$sysmonSvc = Get-Service -Name $sysmonServiceName -ErrorAction SilentlyContinue
if (-not $sysmonSvc) {
    # Also check alternate service name (ARM64 may register as Sysmon64)
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
}
if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") {
    Write-Host "[+] Sysmon already installed and running" -ForegroundColor Green
    Write-Host "[*] Updating configuration..." -ForegroundColor Yellow
    # Re-download config to get latest updates
    $configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    try {
        Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing
        & $sysmonExe -c $configPath 2>$null
        Write-Host "[+] Sysmon config updated" -ForegroundColor Green
    } catch {
        Write-Host "[!] Config update failed: $_" -ForegroundColor Yellow
    }
    exit 0
}

# Create directory
New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null

# Download Sysmon
Write-Host "[*] Downloading Sysmon..." -ForegroundColor Yellow
$sysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZipPath = "$env:TEMP\Sysmon.zip"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Invoke-WebRequest -Uri $sysmonZipUrl -OutFile $sysmonZipPath -UseBasicParsing
    Write-Host "[+] Sysmon downloaded" -ForegroundColor Green
} catch {
    Write-Host "[!] Download failed, trying Chocolatey fallback..." -ForegroundColor Yellow
    choco install sysmon -y --no-progress 2>$null
    if (Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue) {
        Write-Host "[+] Sysmon installed via Chocolatey" -ForegroundColor Green
        exit 0
    }
    Write-Host "[!] Sysmon installation failed" -ForegroundColor Red
    exit 1
}

# Extract
Write-Host "[*] Extracting Sysmon..." -ForegroundColor Yellow
Expand-Archive -Path $sysmonZipPath -DestinationPath $sysmonDir -Force
Remove-Item $sysmonZipPath -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $sysmonExe)) {
    Write-Host "[!] $([System.IO.Path]::GetFileName($sysmonExe)) not found after extraction" -ForegroundColor Red
    # Check for alternate names
    $candidates = @("$sysmonDir\Sysmon64a.exe", "$sysmonDir\Sysmon64.exe", "$sysmonDir\sysmon64.exe", "$sysmonDir\sysmon64a.exe")
    $found = $false
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            $sysmonExe = $candidate
            $found = $true
            Write-Host "[*] Using $candidate" -ForegroundColor Yellow
            break
        }
    }
    if (-not $found) {
        Write-Host "[!] No Sysmon binary found. Contents:" -ForegroundColor Red
        Get-ChildItem $sysmonDir | ForEach-Object { Write-Host "    $_" }
        exit 1
    }
}

# Download SwiftOnSecurity sysmon config (comprehensive, well-tuned)
Write-Host "[*] Downloading SwiftOnSecurity sysmon-config..." -ForegroundColor Yellow
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
try {
    Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing
    Write-Host "[+] Sysmon config downloaded" -ForegroundColor Green
} catch {
    Write-Host "[!] Config download failed, using minimal config" -ForegroundColor Yellow
    # Minimal config that logs everything important
    $minimalConfig = @"
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <FileCreateTime onmatch="exclude" />
    <NetworkConnect onmatch="exclude" />
    <ProcessTerminate onmatch="exclude" />
    <DriverLoad onmatch="exclude" />
    <ImageLoad onmatch="exclude" />
    <CreateRemoteThread onmatch="exclude" />
    <RawAccessRead onmatch="exclude" />
    <ProcessAccess onmatch="exclude" />
    <FileCreate onmatch="exclude" />
    <RegistryEvent onmatch="exclude" />
    <FileCreateStreamHash onmatch="exclude" />
    <PipeEvent onmatch="exclude" />
    <WmiEvent onmatch="exclude" />
    <DnsQuery onmatch="exclude" />
    <FileDelete onmatch="exclude" />
    <ClipboardChange onmatch="exclude" />
    <ProcessTampering onmatch="exclude" />
    <FileBlockExecutable onmatch="exclude" />
    <FileBlockShredding onmatch="exclude" />
  </EventFiltering>
</Sysmon>
"@
    Set-Content -Path $configPath -Value $minimalConfig
}

# Install Sysmon as a service
Write-Host "[*] Installing Sysmon service..." -ForegroundColor Yellow
& $sysmonExe -accepteula -i $configPath 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }

# Verify installation
Start-Sleep -Seconds 3
$sysmonSvc = Get-Service -Name $sysmonServiceName -ErrorAction SilentlyContinue
if (-not $sysmonSvc) {
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
}
if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") {
    Write-Host "[+] Sysmon installed and running (service: $($sysmonSvc.Name))" -ForegroundColor Green
} else {
    # Try starting it
    $svcName = if (Get-Service -Name $sysmonServiceName -ErrorAction SilentlyContinue) { $sysmonServiceName } else { "Sysmon64" }
    Start-Service -Name $svcName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $sysmonSvc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") {
        Write-Host "[+] Sysmon installed and started" -ForegroundColor Green
    } else {
        Write-Host "[!] Sysmon service not running - check logs" -ForegroundColor Red
    }
}

# Add Sysmon to PATH
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$sysmonDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$sysmonDir", "Machine")
    $env:Path = "$sysmonDir;$env:Path"
}

# Add Defender exclusion for Sysmon directory
Add-MpPreference -ExclusionPath $sysmonDir -ErrorAction SilentlyContinue

Write-Host "`n[+] Sysmon installation complete!" -ForegroundColor Green
Write-Host "    Directory:  $sysmonDir" -ForegroundColor Gray
Write-Host "    Config:     $configPath" -ForegroundColor Gray
Write-Host "    Event Log:  Microsoft-Windows-Sysmon/Operational" -ForegroundColor Gray
Write-Host "    Service:    Sysmon64" -ForegroundColor Gray
