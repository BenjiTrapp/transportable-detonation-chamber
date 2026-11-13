# install-scanner-tools.ps1
# Downloads and installs ThreatCheck + DefenderCheck (AV signature scanning tools)
#
# ThreatCheck (by rasta-mouse):
#   - Identifies exact byte sequences that trigger AV/AMSI detection
#   - Supports Defender and AMSI scan engines
#   - Binary splitting approach to pinpoint signature matches
#
# DefenderCheck (by matterpreter):
#   - Similar byte-splitting approach specifically for Windows Defender
#   - Predecessor to ThreatCheck, still useful for quick checks
#
# Expected paths after install:
#   C:\tools\ThreatCheck\bin\ThreatCheck.exe
#   C:\tools\DefenderCheck\bin\DefenderCheck.exe
#
# Run as Administrator
#
# Parameters:
#   -Force   reinstall a tool even if its exe exists (used by the tool updates)
#   -Only    ThreatCheck or DefenderCheck: install just that tool (default: both)
#
# After each successful install the release tag is written to
# C:\tools\ThreatCheck\tdc-release.txt / C:\tools\DefenderCheck\tdc-release.txt.

param(
    [switch]$Force,
    [string]$Only = ""
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Scanner Tools (ThreatCheck + DefenderCheck) ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($Only -and ($Only -notin @("ThreatCheck", "DefenderCheck"))) {
    Write-Host "[!] -Only must be ThreatCheck or DefenderCheck (got '$Only')" -ForegroundColor Red
    exit 1
}
$doThreatCheck = (-not $Only) -or ($Only -eq "ThreatCheck")
$doDefenderCheck = (-not $Only) -or ($Only -eq "DefenderCheck")

# Tag of the latest release of a repo, or $null. The "latest" download URLs do
# not name it, and the tool updates compare it with the marker.
function Get-LatestReleaseTag {
    param([string]$Repo)
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ "User-Agent" = "tdc-installer" } -TimeoutSec 30
        return $release.tag_name
    } catch {
        Write-Host "[!] Could not read the latest $Repo release: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

# Set when a tool that was asked for could not be (re)installed
$updateFailed = $false

# --- ThreatCheck ---
$tcInstallDir = "C:\tools\ThreatCheck"
$tcBinDir = "$tcInstallDir\bin"
$tcExe = "$tcBinDir\ThreatCheck.exe"

if (-not $doThreatCheck) {
    Write-Host "[*] Skipping ThreatCheck (-Only $Only)" -ForegroundColor Gray
} elseif ((Test-Path $tcExe) -and -not $Force) {
    Write-Host "[+] ThreatCheck already installed at $tcExe" -ForegroundColor Green
} else {
    Write-Host "[*] Installing ThreatCheck..." -ForegroundColor Yellow
    $tcTag = Get-LatestReleaseTag "rasta-mouse/ThreatCheck"

    New-Item -ItemType Directory -Path $tcBinDir -Force | Out-Null

    # Try downloading pre-built release from GitHub
    $tcDownloaded = $false
    $tcReleaseUrls = @(
        "https://github.com/rasta-mouse/ThreatCheck/releases/latest/download/ThreatCheck.zip",
        "https://github.com/rasta-mouse/ThreatCheck/releases/download/v1.0.0/ThreatCheck.zip"
    )

    foreach ($url in $tcReleaseUrls) {
        if ($tcDownloaded) { break }
        try {
            Write-Host "[*] Trying: $url" -ForegroundColor Gray
            $zipPath = "$env:TEMP\ThreatCheck.zip"
            Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -TimeoutSec 30
            Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\ThreatCheck_extract" -Force

            # Find ThreatCheck.exe in extracted contents (may be nested)
            $foundExe = Get-ChildItem -Path "$env:TEMP\ThreatCheck_extract" -Recurse -Filter "ThreatCheck.exe" | Select-Object -First 1
            if ($foundExe) {
                # Copy all files from the same directory (includes dependencies)
                # -ErrorAction Stop: a locked ThreatCheck.exe must not count as installed
                Copy-Item -Path "$($foundExe.DirectoryName)\*" -Destination $tcBinDir -Recurse -Force -ErrorAction Stop
                $tcDownloaded = $true
                if ($url -match "/releases/download/([^/]+)/") { $tcTag = $Matches[1] }
                Write-Host "[+] ThreatCheck downloaded from release" -ForegroundColor Green
            } else {
                Write-Host "[!] ThreatCheck.exe not found in archive" -ForegroundColor Yellow
            }

            # Cleanup
            Remove-Item "$env:TEMP\ThreatCheck_extract" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "[!] Download failed: $_" -ForegroundColor Yellow
        }
    }

    # Fallback: build from source if dotnet SDK is available
    # The original project targets .NET Framework 4.8 which is unavailable on ARM64.
    # We retarget to net8.0 (SDK-style csproj) which works on both x64 and ARM64.
    if (-not $tcDownloaded) {
        Write-Host "[*] Pre-built release not available, trying to build from source..." -ForegroundColor Yellow
        $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
        if ($dotnet) {
            try {
                # Defender may quarantine AMSI-related source files — exclude build dirs
                Add-MpPreference -ExclusionPath "$env:TEMP" -ErrorAction SilentlyContinue
                Add-MpPreference -ExclusionPath $tcBinDir -ErrorAction SilentlyContinue
                Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

                $tcSrcDir = "$env:TEMP\ThreatCheck_src"
                Remove-Item $tcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
                git clone --depth 1 "https://github.com/rasta-mouse/ThreatCheck.git" $tcSrcDir 2>$null

                $csproj = Get-ChildItem -Path $tcSrcDir -Recurse -Filter "ThreatCheck.csproj" | Select-Object -First 1
                if ($csproj) {
                    # Retarget to net8.0 SDK-style (original is .NET Framework 4.8)
                    Write-Host "[*] Retargeting ThreatCheck to .NET 8.0..." -ForegroundColor Yellow
                    $sdkCsproj = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>ThreatCheck</AssemblyName>
    <RootNamespace>ThreatCheck</RootNamespace>
    <LangVersion>12</LangVersion>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="CommandLineParser" Version="2.9.1" />
    <PackageReference Include="System.Management.Automation" Version="7.4.1" />
  </ItemGroup>
</Project>
"@
                    Set-Content $csproj.FullName -Value $sdkCsproj
                    # Remove auto-generated AssemblyInfo (SDK generates it)
                    $propsDir = Join-Path $csproj.DirectoryName "Properties"
                    Remove-Item $propsDir -Recurse -Force -ErrorAction SilentlyContinue

                    Write-Host "[*] Building ThreatCheck (.NET 8.0)..." -ForegroundColor Yellow
                    # Built beside the install: an old ThreatCheck.exe must not pass for the build's output
                    $tcBuildOut = "$env:TEMP\ThreatCheck_build"
                    Remove-Item $tcBuildOut -Recurse -Force -ErrorAction SilentlyContinue
                    & dotnet publish $csproj.FullName -c Release -o $tcBuildOut --self-contained false 2>$null
                    if ((Test-Path "$tcBuildOut\ThreatCheck.exe") -or (Test-Path "$tcBuildOut\ThreatCheck.dll")) {
                        Copy-Item -Path "$tcBuildOut\*" -Destination $tcBinDir -Recurse -Force -ErrorAction Stop
                        $tcDownloaded = $true
                        Write-Host "[+] ThreatCheck built from source (net8.0)" -ForegroundColor Green
                    } else {
                        Write-Host "[!] Build produced no output — Defender may have blocked it" -ForegroundColor Yellow
                    }
                }
                Remove-Item $tcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item "$env:TEMP\ThreatCheck_build" -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[!] Build from source failed: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[!] dotnet SDK not found - cannot build from source" -ForegroundColor Yellow
        }
    }

    if ($tcDownloaded -and $tcTag) {
        Set-Content -Path "$tcInstallDir\tdc-release.txt" -Value $tcTag -Encoding ASCII
    }

    if (-not $tcDownloaded) {
        Write-Host "[!] ThreatCheck installation FAILED - no download source available" -ForegroundColor Red
        Write-Host "    Manual install: place ThreatCheck.exe at $tcExe" -ForegroundColor Red
        $updateFailed = $true
    }
}

# --- DefenderCheck ---
$dcInstallDir = "C:\tools\DefenderCheck"
$dcBinDir = "$dcInstallDir\bin"
$dcExe = "$dcBinDir\DefenderCheck.exe"

if (-not $doDefenderCheck) {
    Write-Host "[*] Skipping DefenderCheck (-Only $Only)" -ForegroundColor Gray
} elseif ((Test-Path $dcExe) -and -not $Force) {
    Write-Host "[+] DefenderCheck already installed at $dcExe" -ForegroundColor Green
} else {
    Write-Host "[*] Installing DefenderCheck..." -ForegroundColor Yellow
    $dcTag = Get-LatestReleaseTag "matterpreter/DefenderCheck"

    New-Item -ItemType Directory -Path $dcBinDir -Force | Out-Null

    # Try downloading pre-built release from GitHub
    $dcDownloaded = $false
    $dcReleaseUrls = @(
        "https://github.com/matterpreter/DefenderCheck/releases/latest/download/DefenderCheck.zip",
        "https://github.com/matterpreter/DefenderCheck/releases/latest/download/DefenderCheck.exe"
    )

    foreach ($url in $dcReleaseUrls) {
        if ($dcDownloaded) { break }
        try {
            Write-Host "[*] Trying: $url" -ForegroundColor Gray
            if ($url.EndsWith(".zip")) {
                $zipPath = "$env:TEMP\DefenderCheck.zip"
                Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -TimeoutSec 30
                Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\DefenderCheck_extract" -Force

                $foundExe = Get-ChildItem -Path "$env:TEMP\DefenderCheck_extract" -Recurse -Filter "DefenderCheck.exe" | Select-Object -First 1
                if ($foundExe) {
                    # -ErrorAction Stop: a locked DefenderCheck.exe must not count as installed
                    Copy-Item -Path "$($foundExe.DirectoryName)\*" -Destination $dcBinDir -Recurse -Force -ErrorAction Stop
                    $dcDownloaded = $true
                    Write-Host "[+] DefenderCheck downloaded from release" -ForegroundColor Green
                }
                Remove-Item "$env:TEMP\DefenderCheck_extract" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            } else {
                # Direct exe download
                Invoke-WebRequest -Uri $url -OutFile $dcExe -UseBasicParsing -TimeoutSec 30
                if (Test-Path $dcExe) {
                    $dcDownloaded = $true
                    Write-Host "[+] DefenderCheck downloaded directly" -ForegroundColor Green
                }
            }
        } catch {
            Write-Host "[!] Download failed: $_" -ForegroundColor Yellow
        }
    }

    # Fallback: build from source
    # Same retarget approach as ThreatCheck (original is .NET Framework 4.7.2)
    if (-not $dcDownloaded) {
        Write-Host "[*] Pre-built release not available, trying to build from source..." -ForegroundColor Yellow
        $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
        if ($dotnet) {
            try {
                Add-MpPreference -ExclusionPath "$env:TEMP" -ErrorAction SilentlyContinue
                Add-MpPreference -ExclusionPath $dcBinDir -ErrorAction SilentlyContinue
                Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

                $dcSrcDir = "$env:TEMP\DefenderCheck_src"
                Remove-Item $dcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
                git clone --depth 1 "https://github.com/matterpreter/DefenderCheck.git" $dcSrcDir 2>$null

                $csproj = Get-ChildItem -Path $dcSrcDir -Recurse -Filter "DefenderCheck.csproj" | Select-Object -First 1
                if ($csproj) {
                    # Retarget to net8.0 SDK-style (original is .NET Framework 4.7.2)
                    Write-Host "[*] Retargeting DefenderCheck to .NET 8.0..." -ForegroundColor Yellow
                    $sdkCsproj = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>DefenderCheck</AssemblyName>
    <RootNamespace>DefenderCheck</RootNamespace>
  </PropertyGroup>
</Project>
"@
                    Set-Content $csproj.FullName -Value $sdkCsproj
                    $propsDir = Join-Path $csproj.DirectoryName "Properties"
                    Remove-Item $propsDir -Recurse -Force -ErrorAction SilentlyContinue

                    Write-Host "[*] Building DefenderCheck (.NET 8.0)..." -ForegroundColor Yellow
                    # Built beside the install: an old DefenderCheck.exe must not pass for the build's output
                    $dcBuildOut = "$env:TEMP\DefenderCheck_build"
                    Remove-Item $dcBuildOut -Recurse -Force -ErrorAction SilentlyContinue
                    & dotnet publish $csproj.FullName -c Release -o $dcBuildOut --self-contained false 2>$null
                    if ((Test-Path "$dcBuildOut\DefenderCheck.exe") -or (Test-Path "$dcBuildOut\DefenderCheck.dll")) {
                        Copy-Item -Path "$dcBuildOut\*" -Destination $dcBinDir -Recurse -Force -ErrorAction Stop
                        $dcDownloaded = $true
                        Write-Host "[+] DefenderCheck built from source (net8.0)" -ForegroundColor Green
                    } else {
                        Write-Host "[!] Build produced no output — Defender may have blocked it" -ForegroundColor Yellow
                    }
                }
                Remove-Item $dcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item "$env:TEMP\DefenderCheck_build" -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[!] Build from source failed: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[!] dotnet SDK not found - cannot build from source" -ForegroundColor Yellow
        }
    }

    if ($dcDownloaded -and $dcTag) {
        Set-Content -Path "$dcInstallDir\tdc-release.txt" -Value $dcTag -Encoding ASCII
    }

    if (-not $dcDownloaded) {
        Write-Host "[!] DefenderCheck installation FAILED - no download source available" -ForegroundColor Red
        Write-Host "    Manual install: place DefenderCheck.exe at $dcExe" -ForegroundColor Red
        $updateFailed = $true
    }
}

# --- Summary ---
Write-Host ""
Write-Host "=== Scanner Tools Installation Summary ===" -ForegroundColor Cyan
if (Test-Path $tcExe) {
    Write-Host "[+] ThreatCheck:   INSTALLED at $tcExe" -ForegroundColor Green
} else {
    Write-Host "[-] ThreatCheck:   NOT INSTALLED" -ForegroundColor Red
}
if (Test-Path $dcExe) {
    Write-Host "[+] DefenderCheck: INSTALLED at $dcExe" -ForegroundColor Green
} else {
    Write-Host "[-] DefenderCheck: NOT INSTALLED" -ForegroundColor Red
}
Write-Host ""
# Under -Force a failed (re)install is an error for the caller; without it the script stays tolerant.
if ($Force -and $updateFailed) { exit 1 }
