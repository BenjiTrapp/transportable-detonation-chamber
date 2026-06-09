# install-fibratus.ps1
# Downloads and installs Fibratus v3.0.0 (adversary tradecraft detection)
#
# Fibratus provides:
#   - ETW-based kernel event collection
#   - Behavior-driven rule engine
#   - YARA memory scanning
#   - Eventlog alerts in JSON format (used by DetonatorAgent)
#
# Run as Administrator

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

$fibratusVersion = "3.0.0"
$fibratusInstallDir = "$env:ProgramFiles\Fibratus"
$fibratusMsiUrl = "https://github.com/rabbitstack/fibratus/releases/download/v${fibratusVersion}/fibratus-${fibratusVersion}-amd64.msi"
$fibratusMsiPath = "$env:TEMP\fibratus-${fibratusVersion}-amd64.msi"

# Check if already installed (MSI puts binary in Bin\ subdirectory)
if ((Test-Path "$fibratusInstallDir\Bin\fibratus.exe") -or (Test-Path "$fibratusInstallDir\fibratus.exe")) {
    Write-Host "[+] Fibratus already installed at $fibratusInstallDir" -ForegroundColor Green
    exit 0
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
    Write-Host "[+] Fibratus installed (ZIP method) at $fibratusInstallDir" -ForegroundColor Green
    exit 0
}

# Install MSI silently
Write-Host "[*] Installing Fibratus MSI..." -ForegroundColor Yellow
$msiArgs = "/i `"$fibratusMsiPath`" /qn /norestart INSTALLDIR=`"$fibratusInstallDir`""
$process = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
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
} else {
    Write-Host "[!] Cannot install service - fibratus.exe not found" -ForegroundColor Yellow
}

Write-Host "[+] Fibratus installation complete!" -ForegroundColor Green
