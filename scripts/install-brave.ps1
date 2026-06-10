# install-brave.ps1
# Installs Brave Browser and configures it to open the Detonation Chamber UI on launch
#
# Run as Administrator

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

Write-Host "=== Installing Brave Browser ===" -ForegroundColor Cyan

# --- Install Brave via Chocolatey ---
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Chocolatey not found - cannot install Brave" -ForegroundColor Red
    exit 1
}

$bravePath = "${env:ProgramFiles}\BraveSoftware\Brave-Browser\Application\brave.exe"
if (-not (Test-Path $bravePath)) {
    Write-Host "[*] Installing Brave Browser via Chocolatey..." -ForegroundColor Yellow
    choco install brave -y --no-progress
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
} else {
    Write-Host "[+] Brave Browser already installed" -ForegroundColor Green
}

# Verify installation
$bravePath = "${env:ProgramFiles}\BraveSoftware\Brave-Browser\Application\brave.exe"
if (-not (Test-Path $bravePath)) {
    # Try x86 path
    $bravePath = "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe"
}

if (-not (Test-Path $bravePath)) {
    Write-Host "[!] Brave not found after installation - check logs" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Brave installed at: $bravePath" -ForegroundColor Green

# --- Configure Brave to open Detonation Chamber UI on startup ---
Write-Host "[*] Configuring Brave startup page..." -ForegroundColor Yellow

$webuiUrl = "http://localhost:9000"

# Set Brave policies via registry (machine-level, works for all users)
$policyPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
New-Item -Path $policyPath -Force | Out-Null

# Homepage and startup settings
Set-ItemProperty -Path $policyPath -Name "HomepageLocation" -Value $webuiUrl -Type String
Set-ItemProperty -Path $policyPath -Name "HomepageIsNewTabPage" -Value 0 -Type DWord
Set-ItemProperty -Path $policyPath -Name "RestoreOnStartup" -Value 4 -Type DWord  # 4 = Open a list of URLs

# Startup URLs list
$startupUrlsPath = "$policyPath\RestoreOnStartupURLs"
New-Item -Path $startupUrlsPath -Force | Out-Null
Set-ItemProperty -Path $startupUrlsPath -Name "1" -Value $webuiUrl -Type String

# Disable first-run dialogs and welcome page
Set-ItemProperty -Path $policyPath -Name "PromotionalTabsEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path $policyPath -Name "BookmarkBarEnabled" -Value 1 -Type DWord

Write-Host "[+] Brave configured to open $webuiUrl on startup" -ForegroundColor Green

# --- Create Desktop Shortcut ---
Write-Host "[*] Creating desktop shortcut..." -ForegroundColor Yellow

$desktopPath = "C:\Users\vagrant\Desktop"
if (-not (Test-Path $desktopPath)) {
    $desktopPath = [Environment]::GetFolderPath("Desktop")
}

$shortcutPath = Join-Path $desktopPath "Detonation Chamber.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $bravePath
$shortcut.Arguments = $webuiUrl
$shortcut.WorkingDirectory = Split-Path $bravePath -Parent
$shortcut.Description = "Detonation Chamber - Unified Web UI"
$shortcut.Save()

Write-Host "[+] Desktop shortcut created: $shortcutPath" -ForegroundColor Green

# --- Set Brave as default browser (best effort) ---
Write-Host "[*] Setting Brave as default HTTP handler..." -ForegroundColor Yellow

# Register Brave ProgId for http/https (requires system-level registry)
$braveProgId = "BraveHTML"
try {
    # Set URL associations via registry (may require user consent on newer Windows)
    $assocPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations"
    foreach ($proto in @("http", "https")) {
        $userChoicePath = "$assocPath\$proto\UserChoice"
        # Note: UserChoice is protected on modern Windows, but policies override
        New-Item -Path $userChoicePath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $userChoicePath -Name "ProgId" -Value $braveProgId -ErrorAction SilentlyContinue
    }

    # Also set via policy (more reliable)
    $defaultBrowserPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
    Set-ItemProperty -Path $defaultBrowserPath -Name "DefaultBrowserSettingEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
} catch {
    Write-Host "[!] Could not set default browser via registry (Windows may require interactive consent)" -ForegroundColor Yellow
}

# --- Auto-launch Brave on user login ---
Write-Host "[*] Configuring Brave to auto-launch on login..." -ForegroundColor Yellow

$runKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $runKeyPath -Name "DetonationChamberUI" -Value "`"$bravePath`" $webuiUrl" -Type String

Write-Host "[+] Brave will auto-launch with Detonation Chamber UI on login" -ForegroundColor Green

Write-Host ""
Write-Host "[+] Brave Browser installation complete!" -ForegroundColor Green
Write-Host "    Homepage: $webuiUrl" -ForegroundColor Gray
Write-Host "    Auto-launch on login: enabled" -ForegroundColor Gray
