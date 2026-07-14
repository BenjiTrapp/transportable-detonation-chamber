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

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Scanner Tools (ThreatCheck + DefenderCheck) ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- ThreatCheck ---
$tcInstallDir = "C:\tools\ThreatCheck"
$tcBinDir = "$tcInstallDir\bin"
$tcExe = "$tcBinDir\ThreatCheck.exe"

if (Test-Path $tcExe) {
    Write-Host "[+] ThreatCheck already installed at $tcExe" -ForegroundColor Green
} else {
    Write-Host "[*] Installing ThreatCheck..." -ForegroundColor Yellow

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
                Copy-Item -Path "$($foundExe.DirectoryName)\*" -Destination $tcBinDir -Recurse -Force
                $tcDownloaded = $true
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
                    & dotnet publish $csproj.FullName -c Release -o $tcBinDir --self-contained false 2>$null
                    if ((Test-Path $tcExe) -or (Test-Path "$tcBinDir\ThreatCheck.dll")) {
                        $tcDownloaded = $true
                        Write-Host "[+] ThreatCheck built from source (net8.0)" -ForegroundColor Green
                    } else {
                        Write-Host "[!] Build produced no output — Defender may have blocked it" -ForegroundColor Yellow
                    }
                }
                Remove-Item $tcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[!] Build from source failed: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[!] dotnet SDK not found - cannot build from source" -ForegroundColor Yellow
        }
    }

    if (-not $tcDownloaded) {
        Write-Host "[!] ThreatCheck installation FAILED - no download source available" -ForegroundColor Red
        Write-Host "    Manual install: place ThreatCheck.exe at $tcExe" -ForegroundColor Red
    }
}

# --- DefenderCheck ---
$dcInstallDir = "C:\tools\DefenderCheck"
$dcBinDir = "$dcInstallDir\bin"
$dcExe = "$dcBinDir\DefenderCheck.exe"

if (Test-Path $dcExe) {
    Write-Host "[+] DefenderCheck already installed at $dcExe" -ForegroundColor Green
} else {
    Write-Host "[*] Installing DefenderCheck..." -ForegroundColor Yellow

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
                    Copy-Item -Path "$($foundExe.DirectoryName)\*" -Destination $dcBinDir -Recurse -Force
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
                    & dotnet publish $csproj.FullName -c Release -o $dcBinDir --self-contained false 2>$null
                    if ((Test-Path $dcExe) -or (Test-Path "$dcBinDir\DefenderCheck.dll")) {
                        $dcDownloaded = $true
                        Write-Host "[+] DefenderCheck built from source (net8.0)" -ForegroundColor Green
                    } else {
                        Write-Host "[!] Build produced no output — Defender may have blocked it" -ForegroundColor Yellow
                    }
                }
                Remove-Item $dcSrcDir -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[!] Build from source failed: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[!] dotnet SDK not found - cannot build from source" -ForegroundColor Yellow
        }
    }

    if (-not $dcDownloaded) {
        Write-Host "[!] DefenderCheck installation FAILED - no download source available" -ForegroundColor Red
        Write-Host "    Manual install: place DefenderCheck.exe at $dcExe" -ForegroundColor Red
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
