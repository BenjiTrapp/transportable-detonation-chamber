# install-detection-rules.ps1
# Installs detection rule packs for Rustinel and additional YARA rules
#
# Sources:
#   1. Karib0u/rustinel-rules - Official Rustinel detection packs
#      (Sigma rules, YARA rules, IOC sets - built via Detection-as-Code pipeline)
#   2. elastic/protections-artifacts - Elastic Endpoint YARA rules
#      (Malware signatures, ransomware detection, behavioral EQL)
#
# The built packs are placed where Rustinel can hot-reload them.
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Detection Rules ===" -ForegroundColor Cyan

$rulesBaseDir = "C:\tools\detection-rules"
$rustinelRulesDir = "$rulesBaseDir\rustinel-rules"
$elasticRulesDir = "$rulesBaseDir\elastic-protections"
$rustinelDir = "C:\tools\rustinel"
$packName = "windows-advanced"  # Cumulative: includes essential

# Create base directory
New-Item -ItemType Directory -Path $rulesBaseDir -Force | Out-Null

# ============================================================
# 1. Rustinel Rules (Official packs: Sigma + YARA + IOC)
# ============================================================
Write-Host "`n--- Rustinel Rules (Sigma + YARA + IOC Packs) ---" -ForegroundColor Cyan

if (Test-Path "$rustinelRulesDir\.git") {
    Write-Host "[*] Updating rustinel-rules..." -ForegroundColor Yellow
    Push-Location $rustinelRulesDir
    git pull --ff-only 2>$null
    Pop-Location
} else {
    Write-Host "[*] Cloning rustinel-rules..." -ForegroundColor Yellow
    git clone https://github.com/Karib0u/rustinel-rules.git $rustinelRulesDir
}

# Build the packs using the build tools
if (Test-Path "$rustinelRulesDir\tools\build_packs.py") {
    Write-Host "[*] Building detection packs..." -ForegroundColor Yellow

    # Find Python
    $pythonExe = "C:\Python312\python.exe"
    if (-not (Test-Path $pythonExe)) {
        $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    }

    if ($pythonExe -and (Test-Path $pythonExe)) {
        Push-Location $rustinelRulesDir

        # Create a venv for the build tools if needed
        if (-not (Test-Path "$rustinelRulesDir\.venv\Scripts\python.exe")) {
            Write-Host "[*] Creating build venv..." -ForegroundColor Yellow
            & $pythonExe -m venv "$rustinelRulesDir\.venv"
        }

        $buildPython = "$rustinelRulesDir\.venv\Scripts\python.exe"
        $buildPip = "$rustinelRulesDir\.venv\Scripts\pip.exe"

        # Install build dependencies
        if (Test-Path "$rustinelRulesDir\pyproject.toml") {
            # Try uv first (fast), fallback to pip
            $uvExe = Get-Command uv -ErrorAction SilentlyContinue
            if ($uvExe) {
                Write-Host "[*] Installing build deps with uv..." -ForegroundColor Yellow
                & uv sync --project $rustinelRulesDir 2>$null
                $buildPython = "$rustinelRulesDir\.venv\Scripts\python.exe"
            } else {
                Write-Host "[*] Installing build deps with pip..." -ForegroundColor Yellow
                & $buildPip install --upgrade pip --quiet 2>$null
                # Install the project in development mode to get dependencies
                & $buildPip install -e . --quiet 2>$null
                if ($LASTEXITCODE -ne 0) {
                    # Fallback: install common deps needed by build scripts
                    & $buildPip install pyyaml jsonschema --quiet 2>$null
                }
            }
        }

        # Run pack validation
        Write-Host "[*] Validating rules..." -ForegroundColor Yellow
        & $buildPython tools/validate.py 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] All rules valid" -ForegroundColor Green
        } else {
            Write-Host "[!] Some validation issues (continuing anyway)" -ForegroundColor Yellow
        }

        # Build packs into dist/
        Write-Host "[*] Building packs (this may take a moment)..." -ForegroundColor Yellow
        & $buildPython tools/build_packs.py 2>$null

        if (Test-Path "$rustinelRulesDir\dist\$packName") {
            Write-Host "[+] Pack '$packName' built successfully" -ForegroundColor Green
            # List what was built
            $distDirs = Get-ChildItem "$rustinelRulesDir\dist" -Directory -Name
            Write-Host "    Built packs: $($distDirs -join ', ')" -ForegroundColor Gray
        } else {
            Write-Host "[!] Pack build may have failed, checking dist/..." -ForegroundColor Yellow
            if (Test-Path "$rustinelRulesDir\dist") {
                Get-ChildItem "$rustinelRulesDir\dist" -Name | ForEach-Object { Write-Host "    dist/$_" -ForegroundColor Gray }
            }
        }

        Pop-Location
    } else {
        Write-Host "[!] Python not found - cannot build packs" -ForegroundColor Red
    }
} else {
    Write-Host "[!] rustinel-rules build tools not found" -ForegroundColor Yellow
}

# ============================================================
# 2. Elastic Protections Artifacts (YARA rules)
# ============================================================
Write-Host "`n--- Elastic YARA Rules ---" -ForegroundColor Cyan

if (Test-Path "$elasticRulesDir\.git") {
    Write-Host "[*] Updating elastic protections-artifacts..." -ForegroundColor Yellow
    Push-Location $elasticRulesDir
    git pull --ff-only 2>$null
    Pop-Location
} else {
    Write-Host "[*] Cloning elastic/protections-artifacts (YARA rules)..." -ForegroundColor Yellow
    # Shallow clone to save space (this repo is large)
    git clone --depth 1 https://github.com/elastic/protections-artifacts.git $elasticRulesDir
}

# Count YARA rules
if (Test-Path "$elasticRulesDir\yara") {
    $yaraFileCount = (Get-ChildItem "$elasticRulesDir\yara" -Recurse -Filter "*.yar").Count
    Write-Host "[+] Elastic YARA rules: $yaraFileCount files" -ForegroundColor Green
} else {
    Write-Host "[!] Elastic YARA rules directory not found" -ForegroundColor Yellow
}

# ============================================================
# 3. Configure Rustinel to use the built rules
# ============================================================
Write-Host "`n--- Configuring Rustinel Rules Paths ---" -ForegroundColor Cyan

# Determine paths for the built pack
$packDistDir = "$rustinelRulesDir\dist\$packName"
$sigmaRulesPath = "$packDistDir\rules\sigma"
$yaraRulesPath = "$packDistDir\rules\yara"
$iocDir = "$packDistDir\rules\ioc"

# Create combined YARA directory that includes both rustinel-rules and elastic
$combinedYaraDir = "$rulesBaseDir\yara-combined"
New-Item -ItemType Directory -Path $combinedYaraDir -Force | Out-Null

# Symlink or copy approach - use directory junctions on Windows
# Junction 1: Rustinel pack YARA rules
if (Test-Path $yaraRulesPath) {
    $junctionTarget = "$combinedYaraDir\rustinel"
    if (-not (Test-Path $junctionTarget)) {
        cmd /c mklink /J "$junctionTarget" "$yaraRulesPath" 2>$null | Out-Null
        if (-not (Test-Path $junctionTarget)) {
            # Fallback: copy
            Copy-Item $yaraRulesPath $junctionTarget -Recurse -Force
        }
    }
    Write-Host "[+] Rustinel YARA rules linked" -ForegroundColor Green
}

# Junction 2: Elastic YARA rules
if (Test-Path "$elasticRulesDir\yara") {
    $junctionTarget = "$combinedYaraDir\elastic"
    if (-not (Test-Path $junctionTarget)) {
        cmd /c mklink /J "$junctionTarget" "$elasticRulesDir\yara" 2>$null | Out-Null
        if (-not (Test-Path $junctionTarget)) {
            Copy-Item "$elasticRulesDir\yara" $junctionTarget -Recurse -Force
        }
    }
    Write-Host "[+] Elastic YARA rules linked" -ForegroundColor Green
}

# If the pack didn't build (first run, no uv, etc.), use raw rules from source
if (-not (Test-Path $sigmaRulesPath)) {
    $sigmaRulesPath = "$rustinelRulesDir\rules\sigma\windows"
    Write-Host "[*] Using raw sigma rules from source (pack not built)" -ForegroundColor Yellow
}

# ============================================================
# 4. Write Rustinel config with rule paths
# ============================================================
Write-Host "`n--- Writing Rustinel Configuration ---" -ForegroundColor Cyan

# Build IOC paths (from built pack or source)
$hashesPath = "$iocDir\hashes.txt"
$ipsPath = "$iocDir\ips.txt"
$domainsPath = "$iocDir\domains.txt"
$pathsRegexPath = "$iocDir\paths_regex.txt"

# If IOC files don't exist from build, check source
if (-not (Test-Path $hashesPath)) {
    # IOC source files are YAML, not directly usable without build
    # Create empty placeholder files
    $iocDir = "$rulesBaseDir\ioc"
    New-Item -ItemType Directory -Path $iocDir -Force | Out-Null
    foreach ($f in @("hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt")) {
        if (-not (Test-Path "$iocDir\$f")) {
            New-Item -ItemType File -Path "$iocDir\$f" -Force | Out-Null
        }
    }
    $hashesPath = "$iocDir\hashes.txt"
    $ipsPath = "$iocDir\ips.txt"
    $domainsPath = "$iocDir\domains.txt"
    $pathsRegexPath = "$iocDir\paths_regex.txt"
}

# Escape backslashes for TOML
function ToTomlPath($p) { $p -replace '\\', '\\' }

$configContent = @"
# Rustinel configuration for Detonation Chamber
# Auto-generated by install-detection-rules.ps1
# Docs: https://docs.rustinel.io/getting-started/

[logging]
level = "info"

[alerts]
output_dir = "$(ToTomlPath "$rustinelDir\alerts")"
match_debug = "summary"

[scanner]
# Sigma behavioral detection rules
sigma_enabled = true
sigma_rules_path = "$(ToTomlPath $sigmaRulesPath)"

# YARA file/memory scanning (combined: rustinel-rules + Elastic)
yara_enabled = true
yara_rules_path = "$(ToTomlPath $combinedYaraDir)"

[ioc]
enabled = true
hash_check_enabled = true
max_file_size_mb = 100
default_severity = "high"
hashes_path = "$(ToTomlPath $hashesPath)"
ips_path = "$(ToTomlPath $ipsPath)"
domains_path = "$(ToTomlPath $domainsPath)"
paths_regex_path = "$(ToTomlPath $pathsRegexPath)"

[allowlist]
paths = [
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
]

[response]
enabled = false
prevention_enabled = false
min_severity = "critical"
channel_capacity = 128
allowlist_images = [
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "DetonatorAgent.exe",
    "dotnet.exe",
    "python.exe",
    "fibratus.exe",
    "rustinel.exe",
]
allowlist_paths = [
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\detonator\\",
    "C:\\DetonatorAgent\\",
    "C:\\tools\\detection-rules\\",
]

[reload]
enabled = true
debounce_ms = 2000
"@

Set-Content -Path "$rustinelDir\config.toml" -Value $configContent
Write-Host "[+] Rustinel config written to $rustinelDir\config.toml" -ForegroundColor Green

# ============================================================
# 5. Add Windows Defender exclusions for rule directories
# ============================================================
Add-MpPreference -ExclusionPath $rulesBaseDir -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath $combinedYaraDir -ErrorAction SilentlyContinue

# ============================================================
# Summary
# ============================================================
Write-Host "`n[+] Detection rules installation complete!" -ForegroundColor Green
Write-Host "    Rules base:     $rulesBaseDir" -ForegroundColor Gray
Write-Host "    Rustinel rules: $rustinelRulesDir" -ForegroundColor Gray
Write-Host "    Elastic YARA:   $elasticRulesDir\yara" -ForegroundColor Gray
Write-Host "    Combined YARA:  $combinedYaraDir" -ForegroundColor Gray
Write-Host "    Sigma rules:    $sigmaRulesPath" -ForegroundColor Gray
Write-Host "    IOC directory:  $iocDir" -ForegroundColor Gray
Write-Host "    Pack loaded:    $packName" -ForegroundColor Gray
Write-Host ""
Write-Host "    Rustinel will hot-reload rules on next file change" -ForegroundColor Gray
Write-Host "    (reload.enabled = true, debounce_ms = 2000)" -ForegroundColor Gray
