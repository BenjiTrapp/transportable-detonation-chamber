# install-fibratus.ps1
# Downloads and installs Fibratus (adversary tradecraft detection), pinned to v3.0.0
#
# Fibratus provides:
#   - ETW-based kernel event collection
#   - Behavior-driven rule engine
#   - YARA memory scanning
#   - Eventlog alerts in JSON format (used by DetonatorAgent)
#
# Run as Administrator
#
# Parameters:
#   -Version <x.y.z>  release to install (default: the pin, 3.0.0)
#   -Force            reinstall an existing install (used by the tool updates):
#                     stop the fibratus service, uninstall the old MSI, install
#                     the new one, copy fibratus.yml from C:\vagrant_config
#                     back, install the service and start it. A msiexec exit
#                     code of 3010 or 1641 (reboot needed) is passed on as the
#                     script's exit code.
#
# After each successful install the release tag is written to
# C:\Program Files\Fibratus\tdc-release.txt.

param(
    [string]$Version = "3.0.0",
    [switch]$Force
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Fibratus ===" -ForegroundColor Cyan

# Architecture detection
$isArm64 = ($env:PROCESSOR_ARCHITECTURE -eq "ARM64")
if ($isArm64) {
    Write-Host "[!] ARM64 detected - Fibratus has no native ARM64 build" -ForegroundColor Yellow
    Write-Host "[*] Installing x86_64 build (runs under Windows ARM emulation layer)" -ForegroundColor Yellow
    Write-Host "[*] Note: ETW kernel tracing may have limitations under emulation" -ForegroundColor Yellow
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    Write-Host "[!] -Version must look like 3.0.0 (got '$Version')" -ForegroundColor Red
    exit 1
}
$fibratusVersion = $Version
$fibratusInstallDir = "$env:ProgramFiles\Fibratus"
$fibratusMsiUrl = "https://github.com/rabbitstack/fibratus/releases/download/v${fibratusVersion}/fibratus-${fibratusVersion}-amd64.msi"
$fibratusMsiPath = "$env:TEMP\fibratus-${fibratusVersion}-amd64.msi"

# Check if already installed (MSI puts binary in Bin\ subdirectory)
$alreadyInstalled = (Test-Path "$fibratusInstallDir\Bin\fibratus.exe") -or (Test-Path "$fibratusInstallDir\fibratus.exe")
if ($alreadyInstalled -and -not $Force) {
    Write-Host "[+] Fibratus already installed at $fibratusInstallDir" -ForegroundColor Green
    exit 0
}

# Exit code of msiexec when it asks for a reboot; -Force hands it to the caller.
$rebootExit = 0

function Stop-FibratusService {
    if (Get-Service -Name "fibratus" -ErrorAction SilentlyContinue) {
        Write-Host "[*] Stopping the fibratus service..." -ForegroundColor Yellow
        Stop-Service -Name "fibratus" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}

function Uninstall-FibratusMsi {
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $entry = Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties["DisplayName"] -and $_.DisplayName -like "Fibratus*" } |
        Select-Object -First 1
    if (-not $entry) {
        Write-Host "[!] No Fibratus MSI registered - installing over the existing files" -ForegroundColor Yellow
        return
    }
    if ($entry.PSChildName -notmatch '^\{[0-9A-Fa-f-]{36}\}$') {
        Write-Host "[!] $($entry.DisplayName) has no MSI product code - installing over the existing files" -ForegroundColor Yellow
        return
    }
    Write-Host "[*] Uninstalling $($entry.DisplayName) $($entry.DisplayVersion)..." -ForegroundColor Yellow
    $un = Start-Process msiexec.exe -ArgumentList "/x $($entry.PSChildName) /qn /norestart" -Wait -PassThru
    if ($un.ExitCode -in 3010, 1641) {
        $script:rebootExit = $un.ExitCode
    } elseif ($un.ExitCode -ne 0) {
        Write-Host "[!] MSI uninstall returned exit code $($un.ExitCode)" -ForegroundColor Yellow
    }
}

# Download Fibratus MSI
Write-Host "[*] Downloading Fibratus v${fibratusVersion}..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Invoke-WebRequest -Uri $fibratusMsiUrl -OutFile $fibratusMsiPath -UseBasicParsing
} catch {
    Write-Host "[!] MSI download failed, trying ZIP fallback..." -ForegroundColor Yellow
    $fibratusZipUrl = "https://github.com/rabbitstack/fibratus/releases/download/v${fibratusVersion}/fibratus-${fibratusVersion}-amd64.zip"
    $fibratusZipPath = "$env:TEMP\fibratus-${fibratusVersion}-amd64.zip"
    Invoke-WebRequest -Uri $fibratusZipUrl -OutFile $fibratusZipPath -UseBasicParsing

    # Extract ZIP
    if ($Force) { Stop-FibratusService }
    Write-Host "[*] Extracting Fibratus..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $fibratusInstallDir -Force | Out-Null
    Expand-Archive -Path $fibratusZipPath -DestinationPath $fibratusInstallDir -Force
    Remove-Item $fibratusZipPath -Force -ErrorAction SilentlyContinue

    # Add to PATH
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -notlike "*Fibratus*") {
        [Environment]::SetEnvironmentVariable("Path", "$machinePath;$fibratusInstallDir", "Machine")
        $env:Path = "$fibratusInstallDir;$env:Path"
    }
    Set-Content -Path "$fibratusInstallDir\tdc-release.txt" -Value "v${fibratusVersion}" -Encoding ASCII
    Write-Host "[+] Fibratus installed (ZIP method) at $fibratusInstallDir" -ForegroundColor Green
    exit 0
}

# Reinstall: the service holds the files, the old MSI has to go first
if ($alreadyInstalled) {
    Stop-FibratusService
    Uninstall-FibratusMsi
}

# Install MSI silently
Write-Host "[*] Installing Fibratus MSI..." -ForegroundColor Yellow
$msiArgs = "/i `"$fibratusMsiPath`" /qn /norestart INSTALLDIR=`"$fibratusInstallDir`""
$process = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($process.ExitCode -in 3010, 1641) {
    $rebootExit = $process.ExitCode
}
if ($process.ExitCode -ne 0) {
    Write-Host "[!] MSI install returned exit code $($process.ExitCode), checking if installed anyway..." -ForegroundColor Yellow
}

# Verify installation (MSI installs binary to Bin\ subdirectory)
$fibratusExe = "$fibratusInstallDir\Bin\fibratus.exe"
if (-not (Test-Path $fibratusExe)) {
    $fibratusExe = "$fibratusInstallDir\fibratus.exe"
}
if (Test-Path $fibratusExe) {
    Write-Host "[+] Fibratus installed successfully at $fibratusExe" -ForegroundColor Green
    # Release marker (read by the tool updates)
    Set-Content -Path "$fibratusInstallDir\tdc-release.txt" -Value "v${fibratusVersion}" -Encoding ASCII
} else {
    # Try alternative install location
    $altPaths = @(
        "${env:ProgramFiles}\Fibratus\Bin",
        "${env:ProgramFiles}\Fibratus",
        "${env:ProgramFiles(x86)}\Fibratus\Bin",
        "C:\Fibratus\Bin",
        "C:\Fibratus"
    )
    $found = $false
    foreach ($p in $altPaths) {
        if (Test-Path "$p\fibratus.exe") {
            $fibratusExe = "$p\fibratus.exe"
            $found = $true
            Write-Host "[+] Fibratus found at $p" -ForegroundColor Green
            break
        }
    }
    if (-not $found) {
        Write-Host "[!] Fibratus installation may have failed. Check manually." -ForegroundColor Red
    }
}

# Add Bin directory to PATH
$fibratusBinDir = Split-Path $fibratusExe -Parent
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$fibratusBinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$fibratusBinDir", "Machine")
    $env:Path = "$fibratusBinDir;$env:Path"
}

# Apply custom configuration for JSON event log output
# This is required for DetonatorAgent's fibratus EDR plugin
$fibratusConfigDir = "$fibratusInstallDir\Config"
if (Test-Path $fibratusConfigDir) {
    $configFile = "$fibratusConfigDir\fibratus.yml"
    if (Test-Path "C:\vagrant_config\fibratus.yml") {
        Write-Host "[*] Applying custom Fibratus configuration..." -ForegroundColor Yellow
        Copy-Item "C:\vagrant_config\fibratus.yml" $configFile -Force
    }
}

# Clean up
Remove-Item $fibratusMsiPath -Force -ErrorAction SilentlyContinue

# Install Fibratus as a Windows service
Write-Host "[*] Installing Fibratus service..." -ForegroundColor Yellow
if (Test-Path $fibratusExe) {
    & $fibratusExe install-service 2>$null
    Set-Service -Name "fibratus" -StartupType Automatic -ErrorAction SilentlyContinue
    Write-Host "[+] Fibratus service installed (set to Automatic start)" -ForegroundColor Green
    if ($Force) {
        Start-Service -Name "fibratus" -ErrorAction SilentlyContinue
        Write-Host "[*] fibratus service: $((Get-Service -Name 'fibratus' -ErrorAction SilentlyContinue).Status)" -ForegroundColor Gray
    }
} else {
    Write-Host "[!] Cannot install service - fibratus.exe not found" -ForegroundColor Yellow
}

Write-Host "[+] Fibratus installation complete!" -ForegroundColor Green
if ($Force -and $rebootExit -ne 0) {
    Write-Host "[!] A reboot is needed to finish (msiexec exit code $rebootExit)" -ForegroundColor Yellow
    exit $rebootExit
}
