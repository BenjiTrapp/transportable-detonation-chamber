<#
.SYNOPSIS
    Checks and installs all prerequisites for the Transportable Detonation Chamber
    on Windows (Hyper-V provider).

.DESCRIPTION
    Validates that all required tools and system features are available:
      1. Windows 10/11 with Hyper-V enabled
      2. Administrator privileges
      3. Vagrant >= 2.4
      4. Sufficient disk space (30 GB+)
      5. Sufficient RAM (8 GB minimum)
      6. Windows 11 Vagrant box (auto-downloaded from Vagrant Cloud)
      7. Project files intact

.PARAMETER Fix
    Automatically install/enable missing dependencies where possible.

.EXAMPLE
    .\scripts\check-prerequisites.ps1
    .\scripts\check-prerequisites.ps1 -Fix
#>

param(
    [switch]$Fix
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

# --- Tracking ---
$script:Errors = 0
$script:Warnings = 0

# --- Helpers ---
function Write-Ok      { param($Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn    { param($Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow; $script:Warnings++ }
function Write-Fail    { param($Msg) Write-Host "[-] $Msg" -ForegroundColor Red; $script:Errors++ }
function Write-Info    { param($Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Header  { param($Msg) Write-Host "`n--- $Msg ---" -ForegroundColor White }

# ============================================================================
Write-Host ""
Write-Host "  Transportable Detonation Chamber - Prerequisites Check" -ForegroundColor Cyan
Write-Host "  ======================================================" -ForegroundColor Cyan
Write-Host "  Platform: Windows (Hyper-V)" -ForegroundColor Gray
Write-Host ""

# ============================================================================
Write-Header "Administrator Privileges"
# ============================================================================

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if ($isAdmin) {
    Write-Ok "Running as Administrator"
} else {
    Write-Warn "Not running as Administrator"
    Write-Info "Hyper-V operations require elevation. Re-run as Admin if 'vagrant up' fails."
}

# ============================================================================
Write-Header "Windows Version"
# ============================================================================

$osVersion = [System.Environment]::OSVersion.Version
$osBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
$osName = (Get-CimInstance Win32_OperatingSystem).Caption

if ($osVersion.Major -ge 10 -and [int]$osBuild -ge 19041) {
    Write-Ok "$osName (Build $osBuild)"
} else {
    Write-Fail "Windows 10 version 2004+ or Windows 11 required (detected Build $osBuild)"
}

# ============================================================================
Write-Header "Hyper-V"
# ============================================================================

$hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
if ($hyperv -and $hyperv.State -eq "Enabled") {
    Write-Ok "Hyper-V enabled"
} else {
    Write-Fail "Hyper-V is not enabled"
    if ($Fix -and $isAdmin) {
        Write-Info "Enabling Hyper-V (requires reboot)..."
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart -ErrorAction SilentlyContinue
        $script:Errors--
        Write-Ok "Hyper-V enabled - REBOOT REQUIRED"
        Write-Warn "Please reboot and re-run this script"
    } else {
        Write-Info "Enable with (Admin PowerShell):"
        Write-Info "  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"
        Write-Info "  # Then reboot"
    }
}

# Also check Hyper-V management tools
$hypervMgmt = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -ErrorAction SilentlyContinue
if ($hypervMgmt -and $hypervMgmt.State -eq "Enabled") {
    Write-Ok "Hyper-V PowerShell management tools enabled"
} else {
    Write-Warn "Hyper-V PowerShell tools not enabled (vagrant may still work)"
}

# ============================================================================
Write-Header "Vagrant"
# ============================================================================

$vagrantCmd = Get-Command vagrant -ErrorAction SilentlyContinue
if ($vagrantCmd) {
    $vagrantVersion = (vagrant --version 2>$null)
    Write-Ok "Vagrant installed ($vagrantVersion)"

    # Check version >= 2.4
    if ($vagrantVersion -match '(\d+)\.(\d+)') {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -gt 2 -or ($major -eq 2 -and $minor -ge 4)) {
            Write-Ok "Vagrant version >= 2.4"
        } else {
            Write-Warn "Vagrant version < 2.4 detected. Upgrade recommended for best Hyper-V support."
        }
    }
} else {
    Write-Fail "Vagrant not installed"
    if ($Fix) {
        # Try winget first, then chocolatey
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            Write-Info "Installing Vagrant via winget..."
            winget install HashiCorp.Vagrant --accept-source-agreements --accept-package-agreements
            $script:Errors--
            Write-Ok "Vagrant installed (restart terminal to use)"
        } else {
            $choco = Get-Command choco -ErrorAction SilentlyContinue
            if ($choco) {
                Write-Info "Installing Vagrant via Chocolatey..."
                choco install vagrant -y
                $script:Errors--
                Write-Ok "Vagrant installed (restart terminal to use)"
            } else {
                Write-Info "Install Vagrant from: https://developer.hashicorp.com/vagrant/install"
                Write-Info "  or: winget install HashiCorp.Vagrant"
            }
        }
    } else {
        Write-Info "Install with: winget install HashiCorp.Vagrant"
        Write-Info "  or download from: https://developer.hashicorp.com/vagrant/install"
    }
}

# ============================================================================
Write-Header "Vagrant Box (gusztavvargadr/windows-11)"
# ============================================================================

if ($vagrantCmd) {
    $boxes = vagrant box list 2>$null
    if ($boxes -match "gusztavvargadr/windows-11") {
        Write-Ok "Windows 11 box available (cached locally)"
    } else {
        Write-Warn "Windows 11 box not cached locally"
        Write-Info "It will be auto-downloaded on first 'vagrant up' (~6 GB download)"
        Write-Info "To pre-download: vagrant box add gusztavvargadr/windows-11 --provider hyperv"

        if ($Fix) {
            Write-Info "Pre-downloading Windows 11 box (this may take a while)..."
            vagrant box add gusztavvargadr/windows-11 --provider hyperv 2>$null
            if ($LASTEXITCODE -eq 0) {
                $script:Warnings--
                Write-Ok "Windows 11 box downloaded"
            } else {
                Write-Warn "Box download failed - will retry on 'vagrant up'"
            }
        }
    }
} else {
    Write-Warn "Cannot check box status (Vagrant not installed)"
}

# ============================================================================
Write-Header "System Resources"
# ============================================================================

# RAM check
$totalRamGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
if ($totalRamGB -ge 16) {
    Write-Ok "RAM: ${totalRamGB} GB (8 GB allocated to VM, plenty for host)"
} elseif ($totalRamGB -ge 8) {
    Write-Warn "RAM: ${totalRamGB} GB (VM uses up to 8 GB dynamic - may be tight)"
    Write-Info "Close memory-heavy applications before running the VM"
} else {
    Write-Fail "RAM: ${totalRamGB} GB (minimum 8 GB required, 16 GB recommended)"
}

# Disk space check
$drive = (Get-Location).Drive
$freeGB = [math]::Round((Get-PSDrive $drive.Name).Free / 1GB)
if ($freeGB -ge 30) {
    Write-Ok "Disk space: ${freeGB} GB free on $($drive.Name): (30 GB needed)"
} elseif ($freeGB -ge 15) {
    Write-Warn "Disk space: ${freeGB} GB free on $($drive.Name): (30 GB recommended)"
} else {
    Write-Fail "Disk space: ${freeGB} GB free on $($drive.Name): (30 GB needed for VM)"
}

# ============================================================================
Write-Header "Network (WinRM / PS Remoting)"
# ============================================================================

# Check if WinRM client is configured to allow connections to the VM
$trustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
if ($trustedHosts -eq "*" -or $trustedHosts -match "172\.17\." -or $trustedHosts -match "detonation") {
    Write-Ok "WinRM TrustedHosts configured ($trustedHosts)"
} else {
    Write-Warn "WinRM TrustedHosts may need configuration for PS Remoting to the VM"
    Write-Info "Current value: '$trustedHosts'"
    Write-Info "For 'make.ps1 deploy/services' to work, run (Admin):"
    Write-Info "  Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force"

    if ($Fix -and $isAdmin) {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
        $script:Warnings--
        Write-Ok "WinRM TrustedHosts set to '*'"
    }
}

# ============================================================================
Write-Header "Project Files"
# ============================================================================

$projectDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $projectDir) { $projectDir = Get-Location }

$requiredDirs = @("config", "webui", "rules", "scripts")
foreach ($dir in $requiredDirs) {
    $path = Join-Path $projectDir $dir
    if (Test-Path $path) {
        Write-Ok "Directory exists: $dir\"
    } else {
        Write-Fail "Missing directory: $dir\"
    }
}

$requiredFiles = @(
    "Vagrantfile",
    "config\rustinel-config.toml",
    "config\fibratus.yml",
    "webui\app.py",
    "webui\requirements.txt"
)
foreach ($file in $requiredFiles) {
    $path = Join-Path $projectDir $file
    if (Test-Path $path) {
        Write-Ok "File exists: $file"
    } else {
        Write-Fail "Missing file: $file"
    }
}

# Check rules
$sigmaCount = (Get-ChildItem -Path (Join-Path $projectDir "rules\sigma") -Filter "*.yml" -ErrorAction SilentlyContinue | Measure-Object).Count
$yaraCount = (Get-ChildItem -Path (Join-Path $projectDir "rules\yara") -Filter "*.yar" -ErrorAction SilentlyContinue | Measure-Object).Count
if ($sigmaCount -gt 0) {
    Write-Ok "Sigma rules: $sigmaCount files"
} else {
    Write-Warn "No Sigma rules found in rules\sigma\"
}
if ($yaraCount -gt 0) {
    Write-Ok "YARA rules: $yaraCount files"
} else {
    Write-Warn "No YARA rules found in rules\yara\"
}

# ============================================================================
Write-Header "Summary"
# ============================================================================

Write-Host ""
if ($script:Errors -eq 0 -and $script:Warnings -eq 0) {
    Write-Host "  All prerequisites met! Ready to run:" -ForegroundColor Green
    Write-Host "    .\make.ps1 up" -ForegroundColor White
    Write-Host ""
} elseif ($script:Errors -eq 0) {
    Write-Host "  Prerequisites met with $($script:Warnings) warning(s)." -ForegroundColor Yellow
    Write-Host "  You can proceed, but review the warnings above." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    .\make.ps1 up" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "  $($script:Errors) error(s) and $($script:Warnings) warning(s) found." -ForegroundColor Red
    if (-not $Fix) {
        Write-Host ""
        Write-Host "  Run with -Fix to auto-install missing dependencies:" -ForegroundColor Yellow
        Write-Host "    .\scripts\check-prerequisites.ps1 -Fix" -ForegroundColor White
    }
    Write-Host ""
}

exit $script:Errors
