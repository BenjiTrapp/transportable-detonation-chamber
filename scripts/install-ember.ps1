# install-ember.ps1
# Installs EMBER2024 (thrember) - ML-based malware classifier from FutureComputing4AI
#
# EMBER2024 (https://github.com/FutureComputing4AI/EMBER2024):
#   - Extracts EMBERv3 static features from PE/ELF/PDF/APK files (thrember package)
#   - Scores files with pre-trained LightGBM benchmark models (malicious probability 0..1)
#   - Binary models hosted on HuggingFace (joyce8/EMBER2024-benchmark-models)
#
# Expected layout after install:
#   C:\tools\EMBER2024\EMBER2024\      cloned repo (pip installed)
#   C:\tools\EMBER2024\venv\           dedicated Python venv (thrember + lightgbm)
#   C:\tools\EMBER2024\models\*.model  downloaded LightGBM classifiers
#   C:\tools\EMBER2024\ember_scan.py   CLI wrapper invoked by the Web UI
#
# The Web UI (app.py) calls: venv\Scripts\python.exe ember_scan.py <file> --model <name>
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing EMBER2024 (thrember ML scanner) ===" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$emberRoot   = "C:\tools\EMBER2024"
$repoDir     = "$emberRoot\EMBER2024"
$venvDir     = "$emberRoot\venv"
$modelsDir   = "$emberRoot\models"
$venvPython  = "$venvDir\Scripts\python.exe"
$venvPip     = "$venvDir\Scripts\pip.exe"
$wrapperPath = "$emberRoot\ember_scan.py"

# Binary (malicious/benign) benchmark models we wire into the UI.
# Family / tag models are multiclass and not used by the single-score scanner.
$binaryModels = @(
    "EMBER2024_all.model",
    "EMBER2024_PE.model",
    "EMBER2024_Win32.model",
    "EMBER2024_Win64.model",
    "EMBER2024_Dot_Net.model",
    "EMBER2024_ELF.model",
    "EMBER2024_PDF.model",
    "EMBER2024_APK.model"
)

New-Item -ItemType Directory -Path $emberRoot -Force | Out-Null
New-Item -ItemType Directory -Path $modelsDir -Force | Out-Null

# --- Clone / update the EMBER2024 repo ---
if (Test-Path "$repoDir\pyproject.toml") {
    Write-Host "[+] EMBER2024 repo already present at $repoDir" -ForegroundColor Green
    Write-Host "[*] Pulling latest changes..." -ForegroundColor Yellow
    Push-Location $repoDir
    git pull --ff-only 2>$null
    Pop-Location
} else {
    Write-Host "[*] Cloning EMBER2024..." -ForegroundColor Yellow
    git clone https://github.com/FutureComputing4AI/EMBER2024.git $repoDir
}

# --- Python virtual environment ---
Write-Host "[*] Setting up Python virtual environment..." -ForegroundColor Yellow
$pythonExe = "C:\Python312\python.exe"
if (-not (Test-Path $pythonExe)) {
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
}
if (-not $pythonExe -or -not (Test-Path $pythonExe)) {
    Write-Host "[!] Python not found - cannot set up EMBER2024" -ForegroundColor Red
    return
}
Write-Host "    Using Python: $pythonExe" -ForegroundColor Gray

if (-not (Test-Path $venvPython)) {
    & $pythonExe -m venv $venvDir
}
$venvCheck = & $venvPython -c "print('ok')" 2>&1
if ($venvCheck -notmatch "ok") {
    Write-Host "[*] Venv broken, recreating..." -ForegroundColor Yellow
    Remove-Item $venvDir -Recurse -Force -ErrorAction SilentlyContinue
    & $pythonExe -m venv $venvDir
}

# --- Install thrember + dependencies ---
Write-Host "[*] Installing thrember + dependencies (lightgbm, pefile, ...)..." -ForegroundColor Yellow
Write-Host "    NOTE: LightGBM/polars need prebuilt wheels. On Windows ARM64 these may" -ForegroundColor Gray
Write-Host "    be unavailable - if pip fails here, EMBER scoring will be disabled." -ForegroundColor Gray
& $venvPip install --upgrade pip --quiet 2>$null
Push-Location $repoDir
& $venvPip install . --quiet
$pipExit = $LASTEXITCODE
Pop-Location
# huggingface_hub is a thrember dep, but install explicitly so the download step
# works even if the editable install partially failed.
& $venvPip install "huggingface_hub>=0.32.4" --quiet 2>$null

# thrember does `from signify.authenticode import SignedPEFile`, which signify
# 0.9.x removed from that namespace (relocated to signify.authenticode.signed_file).
# EMBER pins only signify>=0.7.1, so pip resolves the latest and breaks the import.
# Pin the exact baseline that still exports SignedPEFile from signify.authenticode.
& $venvPip install "signify==0.7.1" --quiet 2>$null

if ($pipExit -eq 0) {
    Write-Host "[+] thrember installed" -ForegroundColor Green
} else {
    Write-Host "[!] thrember install returned non-zero - scoring may not work on this platform" -ForegroundColor Yellow
}

# --- Download binary benchmark models from HuggingFace ---
Write-Host "[*] Downloading LightGBM benchmark models (binary classifiers)..." -ForegroundColor Yellow
$modelList = ($binaryModels | ForEach-Object { "'$_'" }) -join ", "
$dlScript = @"
import sys
try:
    from huggingface_hub import hf_hub_download
except Exception as e:
    print('HF_IMPORT_FAILED:', e); sys.exit(2)
repo_id = 'joyce8/EMBER2024-benchmark-models'
models = [$modelList]
ok = 0
for name in models:
    try:
        hf_hub_download(repo_id=repo_id, filename=name, local_dir=r'$modelsDir')
        print('  downloaded', name); ok += 1
    except Exception as e:
        print('  FAILED', name, '-', e)
print('MODELS_OK', ok, 'of', len(models))
"@
$dlFile = "$env:TEMP\ember_download_models.py"
Set-Content -Path $dlFile -Value $dlScript -Encoding UTF8
& $venvPython $dlFile
Remove-Item $dlFile -Force -ErrorAction SilentlyContinue

$modelCount = (Get-ChildItem -Path $modelsDir -Filter "*.model" -ErrorAction SilentlyContinue).Count
if ($modelCount -gt 0) {
    Write-Host "[+] $modelCount model file(s) present in $modelsDir" -ForegroundColor Green
} else {
    Write-Host "[!] No models downloaded - check network / HuggingFace availability" -ForegroundColor Yellow
}

# --- Write the CLI wrapper the Web UI invokes ---
Write-Host "[*] Writing ember_scan.py wrapper..." -ForegroundColor Yellow
$wrapper = @'
#!/usr/bin/env python3
"""EMBER2024 single-file scoring wrapper for the TDC Web UI.

Extracts EMBERv3 features from a file and scores it with a pre-trained
LightGBM benchmark model. Prints a single JSON object to stdout.

Beyond the malicious/benign verdict it also emits an ``explanation`` block:
  * per-feature-group SHAP contributions (why the model decided as it did),
    obtained from ``booster.predict(..., pred_contrib=True)`` and summed over
    each of thrember's 12 feature groups; and
  * concrete raw-feature highlights (file entropy, high-entropy/packed
    sections, notable imported APIs, signature status, PE warnings).
The explanation is best-effort: if anything in it fails the scan verdict is
still returned.
"""
import argparse
import hashlib
import json
import os
import sys
import time

# polars (a thrember dependency) ships only x86_64 wheels. On Windows ARM64 it
# runs under emulation and its CPU-feature probe aborts with
# "unknown feature flag: 'sse3'". Skip the check so thrember can import.
os.environ.setdefault("POLARS_SKIP_CPU_CHECK", "1")

BINARY_MODELS = [
    "EMBER2024_all", "EMBER2024_PE", "EMBER2024_Win32", "EMBER2024_Win64",
    "EMBER2024_Dot_Net", "EMBER2024_ELF", "EMBER2024_PDF", "EMBER2024_APK",
]

# APIs that are common in malware; surfaced when present so the analyst sees
# "what bit". Grouped only for readability of the source list.
SUSPICIOUS_APIS = {
    # code injection / process manipulation
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
    "QueueUserAPC", "SetWindowsHookEx", "OpenProcess", "ReadProcessMemory",
    "NtUnmapViewOfSection", "NtMapViewOfSection", "RtlCreateUserThread",
    # dynamic resolution / anti-analysis
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW", "GetProcAddress",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "OutputDebugStringA",
    # execution
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW", "CreateProcessInternalW",
    # persistence / registry
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    # crypto (ransomware)
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
    "CryptAcquireContextW", "BCryptEncrypt", "CryptImportKey",
    # networking (C2 / download)
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetConnectA", "InternetConnectW", "HttpSendRequestA", "URLDownloadToFileW",
    "URLDownloadToFileA", "WSAStartup", "connect", "send", "recv",
    # discovery / evasion
    "GetAdaptersInfo", "FindFirstFileW", "CreateToolhelp32Snapshot",
    "Process32FirstW", "GetSystemInfo", "GetComputerNameW", "IsWow64Process",
}


def fail(msg):
    print(json.dumps({"tool": "EMBER2024", "error": msg}))
    sys.exit(1)


def _build_explanation(booster, extractor, data, feature_vector):
    """Return a dict explaining the score: per-group SHAP + raw highlights.

    Best-effort; the caller must guard against exceptions.
    """
    import numpy as np

    explanation = {}

    # --- per-group SHAP contributions (log-odds / margin space) ---
    # pred_contrib gives one value per feature plus a trailing bias term.
    try:
        contrib = np.array(booster.predict([feature_vector], pred_contrib=True))[0]
        bias = float(contrib[-1])
        per_feature = contrib[:-1]
        groups = []
        offset = 0
        for f in extractor.features:
            dim = getattr(f, "dim", 0)
            seg = per_feature[offset:offset + dim]
            offset += dim
            val = float(seg.sum())
            groups.append({
                "group": f.name,
                "value": round(val, 4),
                "direction": "malicious" if val >= 0 else "benign",
            })
        groups.sort(key=lambda g: abs(g["value"]), reverse=True)
        explanation["base_value"] = round(bias, 4)
        explanation["contributions"] = groups
    except Exception as e:  # pragma: no cover
        explanation["contributions_error"] = str(e)

    # --- concrete raw-feature highlights ---
    try:
        raw = extractor.raw_features(data)
        details = {}

        general = raw.get("general", {}) or {}
        details["size"] = general.get("size")
        details["file_entropy"] = round(float(general.get("entropy", 0.0)), 3)
        details["has_debug"] = general.get("has_debug")
        details["has_tls"] = general.get("has_tls")
        details["has_resources"] = general.get("has_resources")
        details["exports"] = general.get("exports")
        details["imports"] = general.get("imports")
        details["symbols"] = general.get("symbols")

        # sections: flag high-entropy (likely packed/encrypted) sections
        sec = raw.get("section", {}) or {}
        seclist = sec.get("sections", []) or []
        details["entry_section"] = sec.get("entry")
        sections = []
        for s in seclist:
            sections.append({
                "name": s.get("name", ""),
                "size": s.get("size", 0),
                "vsize": s.get("vsize", 0),
                "entropy": round(float(s.get("entropy", 0.0)), 2),
            })
        # highest-entropy sections first (packing indicator)
        sections.sort(key=lambda x: x["entropy"], reverse=True)
        details["sections"] = sections[:12]
        details["packed_sections"] = [
            s["name"] for s in sections if s["entropy"] >= 7.0
        ]

        # imports: DLL counts + notable/suspicious APIs actually present
        imp = raw.get("imports", {}) or {}
        top_dlls = sorted(
            ((dll, len(funcs or [])) for dll, funcs in imp.items()),
            key=lambda kv: kv[1], reverse=True,
        )
        details["dll_count"] = len(imp)
        details["import_count"] = sum(len(f or []) for f in imp.values())
        details["top_dlls"] = [{"dll": d, "count": c} for d, c in top_dlls[:10]]
        notable = []
        for dll, funcs in imp.items():
            for fn in (funcs or []):
                if fn in SUSPICIOUS_APIS:
                    notable.append({"dll": dll, "api": fn})
        # de-dup while preserving order, cap
        seen = set()
        uniq = []
        for n in notable:
            key = (n["dll"], n["api"])
            if key not in seen:
                seen.add(key)
                uniq.append(n)
        details["notable_apis"] = uniq[:30]

        # strings: high-level counts
        strs = raw.get("strings", {}) or {}
        details["strings"] = {
            "count": strs.get("numstrings"),
            "avg_length": round(float(strs.get("avlength", 0.0)), 1),
            "entropy": round(float(strs.get("entropy", 0.0)), 2),
            "paths": strs.get("paths"),
            "urls": strs.get("urls"),
            "registry": strs.get("registry"),
            "MZ": strs.get("MZ"),
        }

        # authenticode / signature
        auth = raw.get("authenticode", {}) or {}
        details["authenticode"] = auth if isinstance(auth, dict) else {"raw": auth}

        # PE parser warnings (malformed / suspicious structure)
        warns = raw.get("pefilewarnings", {}) or {}
        if isinstance(warns, dict):
            details["pe_warnings"] = [k for k, v in warns.items() if v]
        elif isinstance(warns, list):
            details["pe_warnings"] = warns[:20]

        explanation["details"] = details
    except Exception as e:  # pragma: no cover
        explanation["details_error"] = str(e)

    return explanation


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--model", default="EMBER2024_all")
    ap.add_argument("--models-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "models"))
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--no-explain", action="store_true", help="skip the explanation block")
    args = ap.parse_args()

    if args.model not in BINARY_MODELS:
        fail("Unknown model: %s" % args.model)
    if not os.path.isfile(args.file):
        fail("File not found: %s" % args.file)

    model_path = os.path.join(args.models_dir, args.model + ".model")
    if not os.path.isfile(model_path):
        fail("Model not installed: %s" % model_path)

    try:
        import lightgbm as lgb
        import thrember
        import numpy as np
    except Exception as e:  # pragma: no cover - platform dependent
        fail("thrember/lightgbm not available: %s" % e)

    with open(args.file, "rb") as f:
        data = f.read()

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    try:
        booster = lgb.Booster(model_file=model_path)
        extractor = thrember.PEFeatureExtractor()
        t0 = time.time()
        feature_vector = np.array(extractor.feature_vector(data), dtype=np.float32)
        score = float(booster.predict([feature_vector])[0])
        elapsed_ms = int((time.time() - t0) * 1000)
    except Exception as e:
        fail("Scoring failed: %s" % e)
        return

    malicious = score >= args.threshold
    result = {
        "tool": "EMBER2024",
        "model": args.model,
        "filepath": args.file,
        "sha256": sha256,
        "md5": md5,
        "size": len(data),
        "score": round(float(score), 6),
        "threshold": args.threshold,
        "malicious": bool(malicious),
        "verdict": "malicious" if malicious else "benign",
        "elapsed_ms": elapsed_ms,
    }

    if not args.no_explain:
        try:
            result["explanation"] = _build_explanation(
                booster, extractor, data, feature_vector)
        except Exception as e:
            result["explanation"] = {"error": str(e)}

    print(json.dumps(result))


if __name__ == "__main__":
    main()
'@
Set-Content -Path $wrapperPath -Value $wrapper -Encoding UTF8
Write-Host "[+] Wrapper written to $wrapperPath" -ForegroundColor Green

# --- Smoke test the wrapper (scores the venv python itself, a benign PE) ---
if ((Test-Path $venvPython) -and (Test-Path $wrapperPath) -and $modelCount -gt 0) {
    Write-Host "[*] Smoke testing scorer..." -ForegroundColor Yellow
    $smoke = & $venvPython $wrapperPath $venvPython --model "EMBER2024_all" --models-dir $modelsDir 2>&1
    Write-Host "    $smoke" -ForegroundColor Gray
}

# Windows Defender exclusion so model/feature files are not quarantined
Add-MpPreference -ExclusionPath $emberRoot -ErrorAction SilentlyContinue

Write-Host "`n[+] EMBER2024 installation complete!" -ForegroundColor Green
Write-Host "    Root:    $emberRoot" -ForegroundColor Gray
Write-Host "    Venv:    $venvPython" -ForegroundColor Gray
Write-Host "    Models:  $modelsDir ($modelCount installed)" -ForegroundColor Gray
Write-Host "    Wrapper: $wrapperPath" -ForegroundColor Gray
