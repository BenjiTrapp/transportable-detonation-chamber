<#
.SYNOPSIS
    Transportable Detonation Chamber - Frontend Development Mode

.DESCRIPTION
    Starts the Web UI in development mode with:
    - Live-reload for CSS/JS/HTML changes (auto-refreshes browser)
    - Flask debug mode (auto-restarts on Python changes)
    - Auto-opens browser on startup
    - Optional mock mode for offline development

.EXAMPLE
    .\dev.ps1              Start dev server (default: port 9000)
    .\dev.ps1 -Mock        Start with mock backend services
    .\dev.ps1 -Port 8080   Start on a custom port
    .\dev.ps1 -NoOpen      Don't auto-open the browser
#>

param(
    [Parameter()]
    [int]$Port = 9000,

    [Parameter()]
    [switch]$Mock,

    [Parameter()]
    [switch]$NoOpen,

    [Parameter()]
    [string]$Host = "127.0.0.1"
)

$ErrorActionPreference = 'Stop'
$VenvDir = "webui\.venv"
$PyExe = "$VenvDir\Scripts\python.exe"

# --- Preflight Checks ---

# Check venv exists
if (-not (Test-Path $PyExe)) {
    Write-Host ""
    Write-Host "  [ERROR] Python venv not found." -ForegroundColor Red
    Write-Host "  Run '.\make.ps1 install' first to set up the environment." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Verify watchdog is installed (needed for live-reload)
$watchdogCheck = & $PyExe -c "import watchdog; print('ok')" 2>$null
if ($watchdogCheck -ne 'ok') {
    Write-Host "[dev] Installing missing dependency: watchdog..." -ForegroundColor Yellow
    & $PyExe -m pip install watchdog -q
}

# --- Banner ---
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor DarkCyan
Write-Host "   Transportable Detonation Chamber" -ForegroundColor Cyan -NoNewline
Write-Host " - Dev Mode" -ForegroundColor Yellow
Write-Host "  ================================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "   Features:" -ForegroundColor White
Write-Host "     * Live-reload   CSS/JS/HTML changes refresh browser automatically" -ForegroundColor DarkGray
Write-Host "     * Debug mode    Python changes restart the server" -ForegroundColor DarkGray
Write-Host "     * File watcher  Console shows file change events" -ForegroundColor DarkGray
if ($Mock) {
    Write-Host "     * Mock mode    Backend services are stubbed" -ForegroundColor DarkGray
}
Write-Host ""

# --- Build command args ---
$devArgs = @("webui\dev_server.py", "--port", $Port, "--host", $Host)

if ($Mock) {
    $devArgs += "--mock"
}

if ($NoOpen) {
    $devArgs += "--no-open"
}

# --- Start Dev Server ---
Write-Host "  Starting dev server..." -ForegroundColor Cyan
Write-Host "  URL:  http://${Host}:${Port}" -ForegroundColor Green
Write-Host "  Stop: Ctrl+C" -ForegroundColor DarkGray
Write-Host ""

try {
    & $PyExe $devArgs
} catch {
    # Ctrl+C is expected
    if ($_.Exception.Message -notmatch 'PipelineStoppedException') {
        Write-Host ""
        Write-Host "  [ERROR] Dev server exited with error:" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
    }
} finally {
    Write-Host ""
    Write-Host "  Dev server stopped." -ForegroundColor Yellow
    Write-Host ""
}
