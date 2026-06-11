# install-re-tools.ps1
# Installs reverse engineering and debugging tools:
#   - Detect It Easy (DiE) - PE/ELF/Mach-O identifier and packer detector
#   - WinDbg - Microsoft debugger (64-bit)
#   - Ghidra - NSA reverse engineering framework (requires JDK)
#
# All installed via Chocolatey for clean dependency management.
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Reverse Engineering Tools ===" -ForegroundColor Cyan

# =============================================================================
# 1. DETECT IT EASY (DiE)
# =============================================================================
Write-Host ""
Write-Host "--- [1/3] Detect It Easy ---" -ForegroundColor White

$dieExe = "C:\ProgramData\chocolatey\bin\die.exe"
$dieExeAlt = "C:\Program Files\Detect It Easy\die.exe"

if ((Test-Path $dieExe) -or (Test-Path $dieExeAlt)) {
    Write-Host "[+] Detect It Easy already installed" -ForegroundColor Green
} else {
    Write-Host "[*] Installing Detect It Easy via Chocolatey..." -ForegroundColor Yellow
    choco install die -y --no-progress
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Chocolatey install failed, trying direct download..." -ForegroundColor Yellow
        # Fallback: download from GitHub releases
        $dieVersion = "3.09"
        $dieUrl = "https://github.com/horsicq/DIE-engine/releases/download/$dieVersion/die_win64_portable_${dieVersion}_x64.zip"
        $dieZip = "$env:TEMP\die_portable.zip"
        $dieDir = "C:\tools\die"
        try {
            Invoke-WebRequest -Uri $dieUrl -OutFile $dieZip -UseBasicParsing
            if (-not (Test-Path $dieDir)) { New-Item $dieDir -ItemType Directory -Force | Out-Null }
            Expand-Archive -Path $dieZip -DestinationPath $dieDir -Force
            Remove-Item $dieZip -Force -ErrorAction SilentlyContinue
            # Add to PATH
            $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            if ($machinePath -notlike "*$dieDir*") {
                [Environment]::SetEnvironmentVariable("Path", "$dieDir;$machinePath", "Machine")
                $env:Path = "$dieDir;$env:Path"
            }
            Write-Host "[+] Detect It Easy installed to $dieDir (portable)" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to download DiE: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[+] Detect It Easy installed via Chocolatey" -ForegroundColor Green
    }
}

# Verify DiE
$dieCmd = Get-Command "die" -ErrorAction SilentlyContinue
if (-not $dieCmd) { $dieCmd = Get-Command "diec" -ErrorAction SilentlyContinue }
if ($dieCmd) {
    Write-Host "[+] DiE available: $($dieCmd.Source)" -ForegroundColor Green
} else {
    # Check common locations
    $diePaths = @(
        "C:\ProgramData\chocolatey\bin\die.exe",
        "C:\ProgramData\chocolatey\bin\diec.exe",
        "C:\Program Files\Detect It Easy\die.exe",
        "C:\tools\die\die.exe",
        "C:\tools\die\diec.exe"
    )
    foreach ($p in $diePaths) {
        if (Test-Path $p) { Write-Host "[+] DiE found: $p" -ForegroundColor Green; break }
    }
}

# =============================================================================
# 2. WINDBG (64-BIT)
# =============================================================================
Write-Host ""
Write-Host "--- [2/3] WinDbg (64-bit) ---" -ForegroundColor White

# Check if WinDbg is already available
$windbgPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe",
    "C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe",
    "$env:LocalAppData\Microsoft\WindowsApps\WinDbgX.exe"
)
$windbgFound = $false
foreach ($p in $windbgPaths) {
    if (Test-Path $p) { 
        Write-Host "[+] WinDbg already installed: $p" -ForegroundColor Green
        $windbgFound = $true
        break
    }
}

if (-not $windbgFound) {
    # Try winget first (preferred - gets modern WinDbg Preview on Windows 11)
    $wingetExe = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetExe) {
        Write-Host "[*] Installing WinDbg Preview via winget..." -ForegroundColor Yellow
        winget install --id Microsoft.WinDbg --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] WinDbg Preview installed via winget" -ForegroundColor Green
            $windbgFound = $true
        } else {
            Write-Host "[!] winget install failed (exit: $LASTEXITCODE)" -ForegroundColor Yellow
        }
    }
    if (-not $windbgFound) {
        # Fallback: Windows SDK Debugging Tools via Chocolatey
        Write-Host "[*] Installing WinDbg via Windows SDK Debugging Tools (Chocolatey)..." -ForegroundColor Yellow
        choco install windows-sdk-10-version-2004-windbg -y --no-progress
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] WinDbg installed via Windows SDK package" -ForegroundColor Green
            $windbgFound = $true
        } else {
            Write-Host "[!] Chocolatey SDK package failed, trying direct SDK installer..." -ForegroundColor Yellow
            # Last resort: direct SDK installer
            $sdkUrl = "https://go.microsoft.com/fwlink/?linkid=2272610"
            $sdkInstaller = "$env:TEMP\winsdksetup.exe"
            try {
                Invoke-WebRequest -Uri $sdkUrl -OutFile $sdkInstaller -UseBasicParsing
                Start-Process -FilePath $sdkInstaller -ArgumentList "/features OptionId.WindowsDesktopDebuggers /quiet /norestart" -Wait -NoNewWindow
                Remove-Item $sdkInstaller -Force -ErrorAction SilentlyContinue
                Write-Host "[+] Windows SDK Debugging Tools installed" -ForegroundColor Green
                $windbgFound = $true
            } catch {
                Write-Host "[!] Failed to install WinDbg: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# Ensure WinDbg x64 is in PATH
$windbgDir = $null
foreach ($p in $windbgPaths) {
    $dir = Split-Path $p -Parent
    if (Test-Path $p) { $windbgDir = $dir; break }
}
if ($windbgDir) {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -notlike "*$windbgDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$windbgDir;$machinePath", "Machine")
        $env:Path = "$windbgDir;$env:Path"
        Write-Host "[+] Added WinDbg to PATH: $windbgDir" -ForegroundColor Green
    }
}

# =============================================================================
# 3. GHIDRA
# =============================================================================
Write-Host ""
Write-Host "--- [3/3] Ghidra ---" -ForegroundColor White

$ghidraDir = $null
$ghidraPaths = @(
    "C:\ProgramData\chocolatey\bin\ghidraRun.bat",
    "C:\tools\ghidra\ghidraRun.bat"
)
# Check for existing Ghidra installations
$ghidraInstalled = $false
foreach ($p in $ghidraPaths) {
    if (Test-Path $p) {
        Write-Host "[+] Ghidra already installed: $p" -ForegroundColor Green
        $ghidraInstalled = $true
        break
    }
}
# Also check Program Files
$ghidraGlob = Get-ChildItem "C:\Program Files" -Filter "ghidra*" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $ghidraGlob) { $ghidraGlob = Get-ChildItem "C:\tools" -Filter "ghidra*" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1 }
if ($ghidraGlob) {
    $ghidraInstalled = $true
    Write-Host "[+] Ghidra already installed: $($ghidraGlob.FullName)" -ForegroundColor Green
}

if (-not $ghidraInstalled) {
    # Ghidra requires JDK - install via Chocolatey which handles the dependency
    Write-Host "[*] Installing Ghidra via Chocolatey (includes JDK dependency)..." -ForegroundColor Yellow
    Write-Host "    This may take 5-10 minutes." -ForegroundColor DarkGray

    # Ensure JDK is present (Ghidra 11+ requires JDK 17+)
    $javaHome = $env:JAVA_HOME
    $javaCmd = Get-Command java -ErrorAction SilentlyContinue
    if (-not $javaCmd -and -not $javaHome) {
        Write-Host "[*] Installing OpenJDK 21 (required by Ghidra)..." -ForegroundColor Yellow
        choco install temurin21jdk -y --no-progress
        if ($LASTEXITCODE -ne 0) {
            choco install openjdk --version=21.0.2 -y --no-progress 2>&1 | Out-Null
        }
        # Refresh environment
        $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
        $javaHome = [Environment]::GetEnvironmentVariable("JAVA_HOME", "Machine")
        if ($javaHome) { $env:JAVA_HOME = $javaHome }
    }

    # Install Ghidra
    choco install ghidra -y --no-progress
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Chocolatey Ghidra install failed. Trying direct download..." -ForegroundColor Yellow
        # Fallback: download from GitHub
        $ghidraVersion = "11.3.1"
        $ghidraDate = "20250219"
        $ghidraZipName = "ghidra_${ghidraVersion}_PUBLIC_${ghidraDate}.zip"
        $ghidraUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${ghidraVersion}_build/${ghidraZipName}"
        $ghidraZip = "$env:TEMP\$ghidraZipName"
        $ghidraInstallDir = "C:\tools"

        try {
            Write-Host "[*] Downloading Ghidra $ghidraVersion (~400MB)..." -ForegroundColor Yellow
            Invoke-WebRequest -Uri $ghidraUrl -OutFile $ghidraZip -UseBasicParsing
            Write-Host "[*] Extracting Ghidra..." -ForegroundColor Yellow
            Expand-Archive -Path $ghidraZip -DestinationPath $ghidraInstallDir -Force
            Remove-Item $ghidraZip -Force -ErrorAction SilentlyContinue
            # Find extracted dir
            $extractedDir = Get-ChildItem $ghidraInstallDir -Filter "ghidra_*" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($extractedDir) {
                $ghidraDir = $extractedDir.FullName
                Write-Host "[+] Ghidra installed to $ghidraDir" -ForegroundColor Green
            }
        } catch {
            Write-Host "[!] Failed to download Ghidra: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[+] Ghidra installed via Chocolatey" -ForegroundColor Green
    }
}

# Add Ghidra to PATH if found
if (-not $ghidraDir) {
    $ghidraSearch = Get-ChildItem "C:\tools","C:\Program Files","C:\ProgramData\chocolatey\lib\ghidra" -Filter "ghidraRun.bat" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($ghidraSearch) { $ghidraDir = $ghidraSearch.DirectoryName }
}
if ($ghidraDir) {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -notlike "*$ghidraDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$ghidraDir;$machinePath", "Machine")
        $env:Path = "$ghidraDir;$env:Path"
        Write-Host "[+] Added Ghidra to PATH: $ghidraDir" -ForegroundColor Green
    }
}

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host ""
Write-Host "=== Reverse Engineering Tools Installation Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Detect It Easy (DiE):" -ForegroundColor White
Write-Host "    GUI: die.exe | CLI: diec.exe" -ForegroundColor DarkGray
Write-Host "    Identifies PE/ELF/Mach-O file types, packers, compilers, protectors" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  WinDbg (64-bit):" -ForegroundColor White
Write-Host "    windbg.exe (classic) or WinDbgX.exe (preview)" -ForegroundColor DarkGray
Write-Host "    Kernel/user-mode debugging, crash dump analysis" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Ghidra:" -ForegroundColor White
Write-Host "    ghidraRun.bat (GUI) | analyzeHeadless.bat (CLI)" -ForegroundColor DarkGray
Write-Host "    Disassembly, decompilation, scripting, binary diffing" -ForegroundColor DarkGray
Write-Host ""
