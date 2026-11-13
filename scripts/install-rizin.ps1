# install-rizin.ps1
# Installs Rizin with the rz-ghidra decompiler for the web UI's RIZIN tab.
#
# Rizin (https://rizin.re) is the reverse engineering framework behind Cutter.
# Both come from the Windows package of Cutter v2.5.0, which contains:
#   - rizin.exe (Rizin 0.9.1) and the rz-* tools
#   - lib\rizin\plugins\core_ghidra.dll with rz_ghidra_sleigh (pdg)
#   - vc_redist.x64.exe, the Visual C++ runtime they need
# Taking Rizin and rz-ghidra from one package guarantees that the plugin was
# built for exactly this Rizin. The Cutter GUI is unpacked too but never run.
#
# The package is pinned to the SHA-256 GitHub publishes for the release asset;
# a download that does not match is deleted and nothing is installed.
# Rizin is optional for the lab: when the download, the checksum or the
# self-test fails, the script warns and exits 0, so provisioning goes on and
# the RIZIN tab reports what is missing.
#
# An existing install is kept only if its rizin -v reports 0.9.1 and its
# package marker names the pinned package; otherwise it is replaced, so a new
# pin needs no manual cleanup.
#
# Expected paths after install:
#   C:\tools\cutter\rizin.exe
#   C:\tools\cutter\lib\rizin\plugins\core_ghidra.dll
#   C:\tools\cutter\tdc-package.txt   (package marker)
# The machine-wide SLEIGHHOME points rz-ghidra at its sleigh specs in
# C:\tools\cutter\lib\rizin\plugins\rz_ghidra_sleigh.
# The web UI finds rizin.exe through TDC_RIZIN (default: the path above). It
# runs as SYSTEM and keeps uploads in C:\Windows\Temp\rizin_uploads, which is
# excluded from Defender here.
#
# Note on ARM64 hosts: the package is x64 only; its binaries run under
# Windows' x64 emulation, like Aether and BeaconEye.
#
# Run as Administrator
#
# Parameters (optional):
#   -PackageUrl <url>  download the package from here instead of GitHub, e.g.
#                      a copy the host serves to a VM without internet. The
#                      SHA-256 pin applies to any source.

param(
    [string]$PackageUrl = ""
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest
# The progress bar slows Invoke-WebRequest down badly on a package this size.
$ProgressPreference = "SilentlyContinue"

Write-Host "=== Installing Rizin + rz-ghidra (Cutter v2.5.0 package) ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$PackageName   = "Cutter-v2.5.0-Windows-x86_64.zip"
# "digest" of the asset in https://api.github.com/repos/rizinorg/cutter/releases/tags/v2.5.0
$PackageSha256 = "a04154a03a392dbf5886a629938582f7d23a93636fa0611c3e1c34905b197e69"
$RizinVersion  = "0.9.1"
if (-not $PackageUrl) {
    $PackageUrl = "https://github.com/rizinorg/cutter/releases/download/v2.5.0/$PackageName"
}

$InstallDir     = "C:\tools\cutter"
$RizinExe       = "$InstallDir\rizin.exe"
$GhidraDll      = "$InstallDir\lib\rizin\plugins\core_ghidra.dll"
$SleighHome     = "$InstallDir\lib\rizin\plugins\rz_ghidra_sleigh"
$VcRedist       = "$InstallDir\vc_redist.x64.exe"
$MarkerName     = "tdc-package.txt"
$MarkerText     = "$PackageName sha256:$PackageSha256"
$VersionPattern = "^rizin $([regex]::Escape($RizinVersion))\b"
$UploadDir      = "C:\Windows\Temp\rizin_uploads"

# Ends the script without failing it, so provisioning of the web UI goes on.
function Skip-Install {
    if (Test-Path $RizinExe) {
        Write-Host "    The install in $InstallDir stays as it was. Provisioning goes on." -ForegroundColor Yellow
    } else {
        Write-Host "    Rizin is not installed; the RIZIN tab reports it. Provisioning goes on." -ForegroundColor Yellow
    }
    exit 0
}

function Get-RizinVersionLine {
    try { return ((& $RizinExe -v 2>&1 | Out-String).Trim() -split "`r?`n")[0] } catch { return "" }
}

# --- Defender exclusion for the web UI's uploads ---
# Uploaded samples would otherwise be quarantined before rizin opens them.
New-Item -ItemType Directory -Path $UploadDir -Force -ErrorAction SilentlyContinue | Out-Null
if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
    Add-MpPreference -ExclusionPath $UploadDir -ErrorAction SilentlyContinue
    $excluded = $false
    try { $excluded = @((Get-MpPreference -ErrorAction Stop).ExclusionPath) -contains $UploadDir } catch { }
    if ($excluded) {
        Write-Host "[+] Defender exclusion: $UploadDir" -ForegroundColor Green
    } else {
        Write-Host "[!] Could not add a Defender exclusion for $UploadDir" -ForegroundColor Yellow
    }
}

# --- Download, verify, unpack ---
$installed = $false
$versionLine = ""
if ((Test-Path $RizinExe) -and (Test-Path $GhidraDll)) {
    $markerNow = ""
    try { $markerNow = (Get-Content -Path "$InstallDir\$MarkerName" -Raw -ErrorAction Stop).Trim() } catch { }
    $versionLine = Get-RizinVersionLine
    if (($markerNow -eq $MarkerText) -and ($versionLine -match $VersionPattern)) {
        $installed = $true
        Write-Host "[+] Rizin $RizinVersion already installed at $InstallDir" -ForegroundColor Green
    } else {
        Write-Host "[*] Replacing $InstallDir (rizin -v: '$versionLine', package: '$markerNow')" -ForegroundColor Yellow
    }
}

if (-not $installed) {
    # GetTempPath() rather than $env:TEMP, which only Windows sets
    $zipPath = Join-Path ([IO.Path]::GetTempPath()) $PackageName
    try {
        Write-Host "[*] Downloading $PackageName (~140 MB)..." -ForegroundColor Yellow
        Write-Host "    $PackageUrl" -ForegroundColor DarkGray
        Invoke-WebRequest -Uri $PackageUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 900 -ErrorAction Stop
    } catch {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Write-Host "[!] Download failed: $($_.Exception.Message)" -ForegroundColor Red
        Skip-Install
    }

    # Any failure to hash leaves the value empty, which counts as a mismatch.
    $actualSha256 = ""
    try {
        $actualSha256 = (Get-FileHash -Path $zipPath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { }
    if ($actualSha256 -ne $PackageSha256) {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Write-Host "[!] SHA-256 mismatch: download deleted" -ForegroundColor Red
        Write-Host "    expected $PackageSha256" -ForegroundColor Red
        Write-Host "    got      $actualSha256" -ForegroundColor Red
        Skip-Install
    }
    Write-Host "[+] SHA-256 verified: $PackageSha256" -ForegroundColor Green

    # Unpacked next to the target, so the last steps are renames on one drive:
    # C:\tools\cutter then holds either the whole package or nothing.
    $extractDir = "$InstallDir-extract"
    $oldDir     = "$InstallDir-old"
    try {
        Write-Host "[*] Unpacking to $InstallDir..." -ForegroundColor Yellow
        if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force -ErrorAction Stop }
        if (Test-Path $oldDir) { Remove-Item $oldDir -Recurse -Force -ErrorAction Stop }
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractDir)
        # The archive has a single top folder, Cutter-v2.5.0-Windows-x86_64\.
        # It becomes C:\tools\cutter, so rizin.exe is C:\tools\cutter\rizin.exe.
        $top = Get-ChildItem $extractDir -Directory | Select-Object -First 1
        if (-not $top -or -not (Test-Path (Join-Path $top.FullName "rizin.exe"))) {
            throw "rizin.exe not found in $PackageName"
        }
        Set-Content -Path (Join-Path $top.FullName $MarkerName) -Value $MarkerText -Encoding ASCII -ErrorAction Stop
        # While a rizin from the old install runs (an open RIZIN session), this
        # rename fails and the old install stays untouched.
        if (Test-Path $InstallDir) {
            Rename-Item -Path $InstallDir -NewName (Split-Path $oldDir -Leaf) -ErrorAction Stop
        }
        Move-Item -Path $top.FullName -Destination $InstallDir -ErrorAction Stop
        Remove-Item $oldDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Unpacked to $InstallDir" -ForegroundColor Green
    } catch {
        Write-Host "[!] Unpacking failed: $($_.Exception.Message)" -ForegroundColor Red
        if (-not (Test-Path $InstallDir) -and (Test-Path $oldDir)) {
            Rename-Item -Path $oldDir -NewName (Split-Path $InstallDir -Leaf) -ErrorAction SilentlyContinue
        }
        Skip-Install
    } finally {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Sleigh specs for rz-ghidra ---
# core_ghidra.dll only knows the folder the package was built in on Cutter's
# CI machine (D:/a/cutter/...); without SLEIGHHOME, pdg fails with "No sleigh
# specification for x86:LE:64:default". Set machine-wide for the web UI
# (SYSTEM) and consoles; processes started before keep their environment.
$env:SLEIGHHOME = $SleighHome
if ([Environment]::GetEnvironmentVariable("SLEIGHHOME", "Machine") -ne $SleighHome) {
    [Environment]::SetEnvironmentVariable("SLEIGHHOME", $SleighHome, "Machine")
    Write-Host "[+] SLEIGHHOME set to $SleighHome (restart a running web UI to pick it up)" -ForegroundColor Green
} else {
    Write-Host "[+] SLEIGHHOME is $SleighHome" -ForegroundColor Green
}

# --- Visual C++ runtime ---
# rizin.exe and rz-ghidra need the x64 VC++ 2015-2022 runtime. The package
# carries the redistributable they were built with; it is installed when the
# runtime is missing or older than that.
function Get-VcRuntimeVersion {
    foreach ($key in @("HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
                       "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64")) {
        try {
            $rt = Get-ItemProperty -Path $key -ErrorAction Stop
            if ($rt.Installed -eq 1) {
                return [version]("{0}.{1}.{2}" -f $rt.Major, $rt.Minor, $rt.Bld)
            }
        } catch { }
    }
    return $null
}

if (Test-Path $VcRedist) {
    $vi = (Get-Item $VcRedist).VersionInfo
    $bundledVc = [version]("{0}.{1}.{2}" -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart)
    $installedVc = Get-VcRuntimeVersion
    if ($installedVc -and $installedVc -ge $bundledVc) {
        Write-Host "[+] VC++ x64 runtime $installedVc present" -ForegroundColor Green
    } else {
        Write-Host "[*] Installing VC++ x64 runtime $bundledVc (vc_redist.x64.exe)..." -ForegroundColor Yellow
        try {
            $proc = Start-Process -FilePath $VcRedist -ArgumentList "/install /quiet /norestart" `
                -Wait -PassThru -ErrorAction Stop
            # 1638: a newer runtime is already installed; 3010: installed, reboot pending
            if ($proc.ExitCode -in 0, 1638, 3010) {
                Write-Host "[+] VC++ x64 runtime installed (exit code $($proc.ExitCode))" -ForegroundColor Green
            } else {
                Write-Host "[!] vc_redist.x64.exe exited with $($proc.ExitCode)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[!] vc_redist.x64.exe did not run: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[!] $VcRedist missing - VC++ runtime not checked" -ForegroundColor Yellow
}

# --- Self-test ---
Write-Host "[*] Self-testing rizin..." -ForegroundColor Yellow
$selfTestOk = $true

if (-not $installed) { $versionLine = Get-RizinVersionLine }
if ($versionLine -match $VersionPattern) {
    Write-Host "[+] $versionLine" -ForegroundColor Green
} else {
    Write-Host "[!] rizin -v: expected $RizinVersion, got '$versionLine'" -ForegroundColor Red
    $selfTestOk = $false
}

# Lc lists the core plugins; rz-ghidra appears there as "ghidra" once it loads.
$corePlugins = ""
try { $corePlugins = & $RizinExe -N -qc "Lc" "--" 2>&1 | Out-String } catch { }
if ($corePlugins -match "(?m)^\s*ghidra\b") {
    Write-Host "[+] rz-ghidra loads" -ForegroundColor Green
    # pdg also needs the sleigh specs; rizin.exe itself is a small x64 PE to decompile.
    $decompiled = ""
    try { $decompiled = & $RizinExe -N -e scr.color=0 -qc "af; pdg" $RizinExe 2>&1 | Out-String } catch { }
    if (($decompiled -match "(?m)^\{\s*$") -and ($decompiled -notmatch "Decompiler Error")) {
        Write-Host "[+] pdg decompiles (sleigh specs found)" -ForegroundColor Green
    } else {
        Write-Host "[!] pdg does not decompile:" -ForegroundColor Red
        Write-Host "    $($decompiled.Trim())" -ForegroundColor DarkGray
        $selfTestOk = $false
    }
} else {
    Write-Host "[!] rz-ghidra missing from 'Lc':" -ForegroundColor Red
    Write-Host "    $($corePlugins.Trim())" -ForegroundColor DarkGray
    $selfTestOk = $false
}

Write-Host ""
if ($selfTestOk) {
    Write-Host "[+] Rizin installation complete!" -ForegroundColor Green
} else {
    Write-Host "[!] Rizin is unpacked, but the self-test failed (see above). Provisioning goes on." -ForegroundColor Red
}
Write-Host "    Executable: $RizinExe" -ForegroundColor Gray
Write-Host "    Decompiler: $GhidraDll" -ForegroundColor Gray
Write-Host "    Usage:      rizin.exe -A <file>, then pdg @ main" -ForegroundColor Gray
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    Write-Host "    NOTE: the package is x64 only; rizin.exe runs under x64 emulation." -ForegroundColor Gray
}
exit 0
