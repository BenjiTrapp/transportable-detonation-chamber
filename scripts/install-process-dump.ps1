# install-process-dump.ps1
# Installs Process Dump - recovers unpacked malware code from process memory
#
# Source: https://github.com/glmcdona/Process-Dump  (MIT)
#
# Packers decrypt themselves in memory, so the on-disk sample is not what
# actually runs. Process Dump writes those memory components back to disk as
# loadable PE files, which then feed the chamber's existing static analysis
# (FileMap, PE analyzer, capa, EMBER, YARA, ThreatCheck).
#
# What it adds over PE-Sieve / HollowsHunter (already present via LitterBox):
#   - Clean-hash database: known-good modules are skipped, so a dump of a
#     detonated sample contains only what is actually new on the box
#   - Loose code chunks: executable regions with no PE header at all get a
#     synthesized PE header and import table (dumped as both x86 and x64)
#   - Aggressive import reconstruction: patches every DWORD/QWORD that resolves
#     to a known export, which makes dumps far more readable in IDA/Ghidra
#   - -closemon: hooks process termination and dumps just before exit, which
#     catches short-lived droppers that are gone before any scan starts
#
# Expected paths:
#   C:\tools\ProcessDump\pd64.exe
#   C:\tools\ProcessDump\clean.hashes        (baseline, generated below)
#   C:\dumps\                                (default output folder)
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Process Dump ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ToolRoot  = "C:\tools\ProcessDump"
$DumpDir   = "C:\dumps"
$Exe64     = "$ToolRoot\pd64.exe"
$Exe32     = "$ToolRoot\pd32.exe"
$CleanDb   = "$ToolRoot\clean.hashes"

New-Item -ItemType Directory -Path $ToolRoot -Force | Out-Null
# Process Dump refuses to write into a folder that does not exist yet.
New-Item -ItemType Directory -Path $DumpDir -Force | Out-Null

# --- Download the standalone binaries ---
# The release publishes the executables directly (no archive); they are
# statically linked, so no VC++ redistributable is needed.
$baseUrl = "https://github.com/glmcdona/Process-Dump/releases/latest/download"
$binaries = @(
    @{ Name = "pd64.exe"; Path = $Exe64 },
    @{ Name = "pd32.exe"; Path = $Exe32 }
)

foreach ($bin in $binaries) {
    if (Test-Path $bin.Path) {
        Write-Host "[+] $($bin.Name) already present" -ForegroundColor Green
        continue
    }
    try {
        Write-Host "[*] Downloading $($bin.Name)..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri "$baseUrl/$($bin.Name)" -OutFile $bin.Path `
            -UseBasicParsing -TimeoutSec 300
        $kb = [math]::Round((Get-Item $bin.Path).Length / 1KB)
        Write-Host "[+] $($bin.Name) ($kb KB)" -ForegroundColor Green
    } catch {
        Write-Host "[-] $($bin.Name) failed: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

if (-not (Test-Path $Exe64)) {
    Write-Host "[!] pd64.exe missing - Process Dump not available" -ForegroundColor Red
    exit 0
}

# --- Verify ---
try {
    $help = & $Exe64 --help 2>&1 | Out-String
    if ($help -match "Process Dump|-system") {
        Write-Host "[+] pd64.exe responds to --help" -ForegroundColor Green
    }
} catch {
    Write-Host "[!] Could not run pd64.exe: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- Clean-hash baseline ---
# This has to happen while the box is still clean: every module hashed now is
# one that later dumps can safely skip. Running it after a detonation would
# whitelist the malware itself.
if (Test-Path $CleanDb) {
    $dbKb = [math]::Round((Get-Item $CleanDb).Length / 1KB)
    Write-Host "[+] Clean hash database already exists ($dbKb KB)" -ForegroundColor Green
} else {
    Write-Host "[*] Generating clean hash baseline (running processes)..." -ForegroundColor Yellow
    Write-Host "    This is why the step runs during provisioning - the box is clean now." -ForegroundColor DarkGray
    Push-Location $ToolRoot
    try {
        # genquick covers running processes in well under a minute; the full
        # 'gen' sweep of %WINDIR% and Program Files can take 20+ minutes and is
        # left to the operator (see note at the end).
        $proc = Start-Process -FilePath $Exe64 -ArgumentList "-db", "genquick" `
            -WorkingDirectory $ToolRoot -NoNewWindow -PassThru -Wait
        if ($proc.ExitCode -ne 0) {
            Write-Host "[!] Baseline generation exited with $($proc.ExitCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Baseline generation failed: $($_.Exception.Message)" -ForegroundColor Yellow
    } finally {
        Pop-Location
    }

    if (Test-Path $CleanDb) {
        $dbKb = [math]::Round((Get-Item $CleanDb).Length / 1KB)
        Write-Host "[+] Clean hash database created ($dbKb KB)" -ForegroundColor Green
    } else {
        Write-Host "[!] No clean.hashes produced - dumps will include known-good modules" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "[+] Process Dump installed" -ForegroundColor Green
Write-Host "    Binary:  $Exe64" -ForegroundColor DarkGray
Write-Host "    Dumps:   $DumpDir" -ForegroundColor DarkGray
Write-Host "    Usage:   pd64.exe -pid <PID> -o C:\dumps" -ForegroundColor DarkGray
Write-Host "             pd64.exe -system -o C:\dumps      (everything unknown)" -ForegroundColor DarkGray
Write-Host "             pd64.exe -closemon                 (dump on process exit)" -ForegroundColor DarkGray
Write-Host "    Tip:     run 'pd64.exe -db gen' once on the clean box for a" -ForegroundColor DarkGray
Write-Host "             fuller baseline (slow: also walks WINDIR and Program Files)" -ForegroundColor DarkGray
