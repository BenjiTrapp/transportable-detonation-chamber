# install-capa.ps1
# Installs Mandiant capa - static capability detection for executables.
#
# capa (https://github.com/mandiant/capa):
#   - Identifies capabilities in PE / .NET / ELF / shellcode via a rule engine
#   - Maps findings to MITRE ATT&CK and the Malware Behavior Catalog (MBC)
#   - Fully static, explainable (rule + address), no execution required
#
# Complements EMBER2024: EMBER answers "is it malicious?" (ML score),
# capa answers "what can it do?" (ATT&CK-mapped capabilities).
#
# We use the precompiled standalone release (capa.exe) which bundles the
# rules + signatures, so no venv / rule download is needed.
#
# Expected path after install:
#   C:\tools\capa\capa.exe
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing capa (static capability detection) ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$capaInstallDir = "C:\tools\capa"
$capaExe = "$capaInstallDir\capa.exe"
$fallbackVersion = "v9.4.0"  # used if the GitHub API is unreachable

if (Test-Path $capaExe) {
    Write-Host "[+] capa already installed at $capaExe" -ForegroundColor Green
    return
}

New-Item -ItemType Directory -Path $capaInstallDir -Force | Out-Null

# Resolve the latest Windows release asset URL (fall back to a pinned version).
$assetUrl = $null
try {
    Write-Host "[*] Querying latest capa release..." -ForegroundColor Yellow
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/mandiant/capa/releases/latest" `
        -Headers @{ "User-Agent" = "tdc-installer" } -TimeoutSec 30
    $asset = $release.assets | Where-Object { $_.name -match "^capa-.*-windows\.zip$" } | Select-Object -First 1
    if ($asset) {
        $assetUrl = $asset.browser_download_url
        Write-Host "    Latest: $($release.tag_name) ($($asset.name))" -ForegroundColor Gray
    }
} catch {
    Write-Host "[!] GitHub API query failed: $_" -ForegroundColor Yellow
}
if (-not $assetUrl) {
    $assetUrl = "https://github.com/mandiant/capa/releases/download/$fallbackVersion/capa-$fallbackVersion-windows.zip"
    Write-Host "[*] Falling back to pinned version $fallbackVersion" -ForegroundColor Yellow
}

# Download + extract capa.exe
$zipPath = "$env:TEMP\capa-windows.zip"
$extractDir = "$env:TEMP\capa_extract"
try {
    Write-Host "[*] Downloading: $assetUrl" -ForegroundColor Gray
    Invoke-WebRequest -Uri $assetUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 120
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $foundExe = Get-ChildItem -Path $extractDir -Recurse -Filter "capa.exe" | Select-Object -First 1
    if ($foundExe) {
        Copy-Item -Path "$($foundExe.DirectoryName)\*" -Destination $capaInstallDir -Recurse -Force
        Write-Host "[+] capa installed to $capaInstallDir" -ForegroundColor Green
    } else {
        Write-Host "[!] capa.exe not found in archive" -ForegroundColor Red
    }
} catch {
    Write-Host "[!] Download/extract failed: $_" -ForegroundColor Red
} finally {
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Windows Defender exclusion (capa.exe + bundled rules can trip heuristics)
Add-MpPreference -ExclusionPath $capaInstallDir -ErrorAction SilentlyContinue

# Smoke test: capa versions itself without a target
if (Test-Path $capaExe) {
    Write-Host "[*] Smoke testing capa..." -ForegroundColor Yellow
    $ver = & $capaExe --version 2>&1
    Write-Host "    $ver" -ForegroundColor Gray
    Write-Host "    NOTE: no Windows ARM64 build exists; the x64 capa.exe runs under emulation." -ForegroundColor Gray
}

Write-Host "`n[+] capa installation complete!" -ForegroundColor Green
Write-Host "    Executable: $capaExe" -ForegroundColor Gray
