# install-hunt-sleeping-beacons.ps1
# Installs Hunt-Sleeping-Beacons - a callstack scanner for identifying sleeping C2 beacons
#
# Source: https://github.com/thefLink/Hunt-Sleeping-Beacons
# Requires: Visual Studio Build Tools 2022 (C++ Desktop workload)
#
# The tool scans process callstacks to identify IOCs indicating:
#   - Unbacked/private memory in callstacks
#   - Non-executable memory pages
#   - Module stomping (copy-on-write detection)
#   - Suspicious APC-based sleepmasks
#   - Timer-based sleepmasks (enumerating timer callbacks)
#   - Abnormal intermodular calls (module proxying)
#   - Return address spoofing
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Hunt-Sleeping-Beacons ===" -ForegroundColor Cyan

$ToolRoot = "C:\tools\Hunt-Sleeping-Beacons"
$SourceDir = "C:\tools\Hunt-Sleeping-Beacons-src"
$RepoUrl = "https://github.com/thefLink/Hunt-Sleeping-Beacons.git"

# --- Detect architecture ---
$arch = if ([System.Environment]::Is64BitOperatingSystem) {
    $procArch = $env:PROCESSOR_ARCHITECTURE
    if ($procArch -eq "ARM64") { "ARM64" } else { "x64" }
} else { "x86" }
Write-Host "[*] Detected architecture: $arch" -ForegroundColor Yellow

# --- Install Visual Studio Build Tools 2022 (C++ workload) ---
$msbuildPaths = @(
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
)

$msbuildExe = $null
foreach ($p in $msbuildPaths) {
    if (Test-Path $p) { $msbuildExe = $p; break }
}

if (-not $msbuildExe) {
    Write-Host "[*] Installing Visual Studio Build Tools 2022 (C++ Desktop workload)..." -ForegroundColor Yellow
    Write-Host "    This may take 10-20 minutes on first install." -ForegroundColor DarkGray

    # Install via Chocolatey with C++ workload
    choco install visualstudio2022buildtools -y --no-progress --package-parameters `
        "--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --includeRecommended --passive --norestart"

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Chocolatey install returned non-zero, trying direct VS installer..." -ForegroundColor Yellow
        # Fallback: download and run VS Build Tools installer directly
        $vsInstallerUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
        $vsInstaller = "$env:TEMP\vs_buildtools.exe"
        Invoke-WebRequest -Uri $vsInstallerUrl -OutFile $vsInstaller -UseBasicParsing
        Start-Process -FilePath $vsInstaller -ArgumentList `
            "--quiet", "--wait", "--norestart", `
            "--add", "Microsoft.VisualStudio.Workload.VCTools", `
            "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", `
            "--add", "Microsoft.VisualStudio.Component.VC.Tools.ARM64", `
            "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621", `
            "--includeRecommended" `
            -Wait -NoNewWindow
        Remove-Item $vsInstaller -Force -ErrorAction SilentlyContinue
    }

    # Re-check for MSBuild
    foreach ($p in $msbuildPaths) {
        if (Test-Path $p) { $msbuildExe = $p; break }
    }

    if (-not $msbuildExe) {
        Write-Host "[!] MSBuild not found after installation. Build will be skipped." -ForegroundColor Red
        Write-Host "    You can manually build after installing Visual Studio Build Tools 2022." -ForegroundColor DarkGray
    } else {
        Write-Host "[+] Visual Studio Build Tools installed: $msbuildExe" -ForegroundColor Green
    }
} else {
    Write-Host "[+] MSBuild already available: $msbuildExe" -ForegroundColor Green
}

# --- Clone the repository ---
if (-not (Test-Path "$SourceDir\src\Hunt-Sleeping-Beacons.sln")) {
    Write-Host "[*] Cloning Hunt-Sleeping-Beacons..." -ForegroundColor Yellow
    if (Test-Path $SourceDir) { Remove-Item $SourceDir -Recurse -Force }
    git clone $RepoUrl $SourceDir 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to clone Hunt-Sleeping-Beacons" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Repository cloned to $SourceDir" -ForegroundColor Green
} else {
    Write-Host "[+] Hunt-Sleeping-Beacons source already present at $SourceDir" -ForegroundColor Green
    Push-Location $SourceDir
    git pull --ff-only 2>&1 | Out-Null
    Pop-Location
}

# --- Build the project ---
$buildSuccess = $false
if ($msbuildExe) {
    Write-Host "[*] Building Hunt-Sleeping-Beacons (Release|$arch)..." -ForegroundColor Yellow

    $slnFile = "$SourceDir\src\Hunt-Sleeping-Beacons.sln"
    $platform = $arch  # x64, ARM64, or x86 (matches solution config)

    # Run MSBuild
    $buildArgs = @(
        $slnFile,
        "/p:Configuration=Release",
        "/p:Platform=$platform",
        "/m",
        "/verbosity:minimal",
        "/nologo"
    )

    & $msbuildExe @buildArgs
    if ($LASTEXITCODE -eq 0) {
        $buildSuccess = $true
        Write-Host "[+] Build succeeded" -ForegroundColor Green
    } else {
        Write-Host "[!] Build failed with exit code $LASTEXITCODE" -ForegroundColor Red
        Write-Host "    Attempting NuGet restore and retry..." -ForegroundColor Yellow

        # Try restoring NuGet packages first
        & $msbuildExe $slnFile /t:Restore /p:Configuration=Release /p:Platform=$platform /verbosity:minimal /nologo 2>&1 | Out-Null
        & $msbuildExe @buildArgs
        if ($LASTEXITCODE -eq 0) {
            $buildSuccess = $true
            Write-Host "[+] Build succeeded after restore" -ForegroundColor Green
        } else {
            Write-Host "[!] Build failed. Source is available at $SourceDir for manual compilation." -ForegroundColor Red
        }
    }
}

# --- Deploy built binary ---
if (-not (Test-Path $ToolRoot)) {
    New-Item $ToolRoot -ItemType Directory -Force | Out-Null
}

if ($buildSuccess) {
    # Find the built executable
    $outputDirs = @(
        "$SourceDir\src\Hunt-Sleeping-Beacons\$platform\Release",
        "$SourceDir\src\$platform\Release",
        "$SourceDir\src\Hunt-Sleeping-Beacons\Release",
        "$SourceDir\x64\Release",
        "$SourceDir\ARM64\Release"
    )

    $builtExe = $null
    foreach ($dir in $outputDirs) {
        $candidate = Join-Path $dir "Hunt-Sleeping-Beacons.exe"
        if (Test-Path $candidate) { $builtExe = $candidate; break }
        # Also check with different casing
        $candidates = Get-ChildItem $dir -Filter "*.exe" -ErrorAction SilentlyContinue
        if ($candidates) {
            $builtExe = $candidates[0].FullName
            break
        }
    }

    if ($builtExe) {
        Copy-Item $builtExe "$ToolRoot\Hunt-Sleeping-Beacons.exe" -Force
        Write-Host "[+] Binary deployed: $ToolRoot\Hunt-Sleeping-Beacons.exe" -ForegroundColor Green
    } else {
        Write-Host "[!] Could not locate built executable in expected output directories" -ForegroundColor Yellow
        Write-Host "    Searching recursively..." -ForegroundColor DarkGray
        $found = Get-ChildItem $SourceDir -Filter "Hunt-Sleeping-Beacons.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            Copy-Item $found.FullName "$ToolRoot\Hunt-Sleeping-Beacons.exe" -Force
            Write-Host "[+] Binary found and deployed: $ToolRoot\Hunt-Sleeping-Beacons.exe" -ForegroundColor Green
        } else {
            Write-Host "[!] No executable found after build. Check build output manually." -ForegroundColor Red
        }
    }
} else {
    Write-Host "[!] Build was skipped or failed. Source available at: $SourceDir" -ForegroundColor Yellow
    Write-Host "    To build manually: msbuild $SourceDir\src\Hunt-Sleeping-Beacons.sln /p:Configuration=Release /p:Platform=$arch" -ForegroundColor DarkGray
}

# --- Add to PATH ---
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$ToolRoot*") {
    [Environment]::SetEnvironmentVariable("Path", "$ToolRoot;$currentPath", "Machine")
    $env:Path = "$ToolRoot;$env:Path"
    Write-Host "[+] Added $ToolRoot to system PATH" -ForegroundColor Green
}

# --- Create a convenience batch wrapper (for use without full path) ---
$wrapperContent = @"
@echo off
REM Hunt-Sleeping-Beacons wrapper
REM Usage: hsb [options]
REM   -p / --pid {PID}    Scan a specific process
REM   --dotnet             Include .NET processes (prone to false positives)
REM   --commandline        Show command lines for suspicious processes
REM   -h / --help          Show help
"$ToolRoot\Hunt-Sleeping-Beacons.exe" %*
"@
Set-Content "$ToolRoot\hsb.bat" $wrapperContent -Force
Write-Host "[+] Created shortcut: hsb.bat (use 'hsb' from any directory)" -ForegroundColor Green

# --- Verify installation ---
Write-Host ""
Write-Host "=== Hunt-Sleeping-Beacons Installation Complete ===" -ForegroundColor Cyan
Write-Host "  Binary:  $ToolRoot\Hunt-Sleeping-Beacons.exe" -ForegroundColor White
Write-Host "  Source:  $SourceDir" -ForegroundColor White
Write-Host "  Shortcut: hsb (from any directory)" -ForegroundColor White
Write-Host ""
Write-Host "  Usage:" -ForegroundColor White
Write-Host "    Hunt-Sleeping-Beacons.exe           # Scan all processes" -ForegroundColor DarkGray
Write-Host "    Hunt-Sleeping-Beacons.exe -p 1234   # Scan specific PID" -ForegroundColor DarkGray
Write-Host "    Hunt-Sleeping-Beacons.exe --commandline  # Show cmdlines" -ForegroundColor DarkGray
Write-Host ""

if (Test-Path "$ToolRoot\Hunt-Sleeping-Beacons.exe") {
    Write-Host "[+] Hunt-Sleeping-Beacons ready to use" -ForegroundColor Green
} else {
    Write-Host "[!] Binary not present - manual build required (see source dir above)" -ForegroundColor Yellow
}
