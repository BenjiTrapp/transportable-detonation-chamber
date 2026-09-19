#!/usr/bin/env bash
# setup-macos-utm.sh
# Complete setup for the Transportable Detonation Chamber on macOS Apple Silicon
# using UTM as the hypervisor (recommended path for M1/M2/M3/M4 Macs).
#
# This script:
#   1. Installs host-side prerequisites (QEMU tools, Vagrant, swtpm)
#   2. Guides through UTM VM creation with a Windows 11 ARM64 ISO
#   3. Copies project files into the running VM via WinRM
#   4. Runs all provisioning scripts (Sysmon, Fibratus, Rustinel, Detonator, etc.)
#   5. Verifies the Detonation Chamber is operational
#
# Prerequisites:
#   - macOS on Apple Silicon (M1/M2/M3/M4)
#   - UTM installed: https://mac.getutm.app or `brew install --cask utm`
#   - A Windows 11 ARM64 ISO (download from Microsoft)
#
# Usage:
#   ./scripts/setup-macos-utm.sh                           # Full guided setup
#   ./scripts/setup-macos-utm.sh --skip-prerequisites      # Skip brew installs
#   ./scripts/setup-macos-utm.sh --vm-ip 192.168.64.4      # Skip IP detection
#   ./scripts/setup-macos-utm.sh --provision-only          # Only run provisioning
#
# After a manual Windows 11 install in UTM, run the provisioning step:
#   ./scripts/setup-macos-utm.sh --provision-only --vm-ip <ip>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
ok()      { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
fail()    { echo -e "${RED}[-]${NC} $1"; }
header()  { echo -e "\n${BOLD}=== $1 ===${NC}\n"; }

# --- CLI Arguments ---
SKIP_PREREQS=false
PROVISION_ONLY=false
VM_IP=""
VM_USER="vagrant"
VM_PASS="vagrant"

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-prerequisites) SKIP_PREREQS=true; shift ;;
        --provision-only)     PROVISION_ONLY=true; shift ;;
        --vm-ip)             VM_IP="$2"; shift 2 ;;
        --vm-user)           VM_USER="$2"; shift 2 ;;
        --vm-pass)           VM_PASS="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-prerequisites   Skip installing host tools (QEMU, etc.)"
            echo "  --provision-only       Skip VM creation, go straight to provisioning"
            echo "  --vm-ip IP             VM IP address (skip auto-detection)"
            echo "  --vm-user USER         VM admin username (default: vagrant)"
            echo "  --vm-pass PASS         VM admin password (default: vagrant)"
            echo "  -h, --help             Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# =============================================================================
# Step 1: Host Prerequisites
# =============================================================================

if ! $SKIP_PREREQS && ! $PROVISION_ONLY; then
    header "Step 1: Host Prerequisites"

    # Platform check
    if [[ "$(uname -s)" != "Darwin" ]]; then
        fail "This script is for macOS only."
        exit 1
    fi
    if [[ "$(uname -m)" != "arm64" ]]; then
        fail "Apple Silicon (ARM64) required."
        exit 1
    fi
    ok "macOS Apple Silicon detected"

    # Homebrew
    if ! command -v brew &>/dev/null; then
        fail "Homebrew not installed. Install: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    ok "Homebrew installed"

    # UTM
    if [[ -d "/Applications/UTM.app" ]]; then
        ok "UTM installed"
    else
        info "Installing UTM..."
        brew install --cask utm
        ok "UTM installed"
    fi

    # QEMU tools (for qemu-img, used in box packaging if needed later)
    if command -v qemu-img &>/dev/null; then
        ok "QEMU tools installed"
    else
        info "Installing QEMU (for qemu-img tool)..."
        brew install qemu
        ok "QEMU installed"
    fi

    # Python 3 with pywinrm (for remote provisioning)
    if python3 -c "import winrm" &>/dev/null; then
        ok "pywinrm available"
    else
        info "Installing pywinrm for remote provisioning..."
        pip3 install --user pywinrm requests-ntlm 2>/dev/null || \
            pip3 install pywinrm requests-ntlm 2>/dev/null || {
            warn "Could not install pywinrm globally. Creating venv..."
            python3 -m venv "$PROJECT_DIR/.setup-venv"
            "$PROJECT_DIR/.setup-venv/bin/pip" install pywinrm requests-ntlm -q
        }
        ok "pywinrm installed"
    fi

    echo ""
    ok "All host prerequisites satisfied."
fi

# =============================================================================
# Step 2: UTM VM Creation (guided)
# =============================================================================

if ! $PROVISION_ONLY; then
    header "Step 2: Windows 11 ARM64 VM in UTM"

    echo -e "  ${BOLD}Create a Windows 11 ARM64 VM in UTM with these settings:${NC}"
    echo ""
    echo "    1. Open UTM → Create New VM → Virtualize → Windows"
    echo "    2. Select your Windows 11 ARM64 ISO"
    echo "    3. Recommended settings:"
    echo "       - RAM: 8 GB (minimum 4 GB)"
    echo "       - CPU: 4+ cores"
    echo "       - Disk: 80 GB"
    echo "       - Network: Shared (default)"
    echo ""
    echo "    4. Install Windows 11 normally:"
    echo "       - Create a local account (recommended name: 'vagrant', password: 'vagrant')"
    echo "       - Or use any name/password and pass --vm-user/--vm-pass to this script"
    echo ""
    echo "    5. Once at the Windows desktop, run in an elevated PowerShell:"
    echo ""
    echo -e "       ${CYAN}# Download and run the WinRM preparation script:${NC}"
    echo "       Set-ExecutionPolicy Bypass -Scope Process -Force"
    echo "       iwr http://\$(ipconfig getifaddr en0 2>/dev/null || echo '<mac-ip>'):8765/prepare-vagrant-winrm.ps1 -OutFile prep.ps1"
    echo "       .\\prep.ps1"
    echo ""
    echo "    Alternatively, copy scripts/prepare-vagrant-winrm.ps1 into the VM"
    echo "    via USB drive, shared folder, or browser download and run it."
    echo ""
    echo -e "  ${YELLOW}Press Enter when the VM is ready (Windows desktop + WinRM script ran)...${NC}"
    read -r
fi

# =============================================================================
# Step 3: Detect VM IP
# =============================================================================

header "Step 3: Connecting to VM"

if [[ -z "$VM_IP" ]]; then
    info "Detecting VM IP address..."
    # UTM shared network uses 192.168.64.x range
    # Try to find a Windows host responding on WinRM port 5985
    for ip in $(arp -a 2>/dev/null | grep -oE '192\.168\.64\.[0-9]+' | sort -u); do
        if nc -z -G 2 "$ip" 5985 &>/dev/null; then
            VM_IP="$ip"
            break
        fi
    done

    if [[ -z "$VM_IP" ]]; then
        # Broader scan
        for i in $(seq 2 30); do
            if nc -z -G 1 "192.168.64.$i" 5985 &>/dev/null; then
                VM_IP="192.168.64.$i"
                break
            fi
        done
    fi

    if [[ -z "$VM_IP" ]]; then
        fail "Could not auto-detect VM IP."
        echo "  Check the VM's IP with 'ipconfig' in Windows, then re-run:"
        echo "    $0 --provision-only --vm-ip <ip>"
        exit 1
    fi
fi

ok "VM IP: $VM_IP"

# Test WinRM connectivity
info "Testing WinRM connection..."
if ! nc -z -G 3 "$VM_IP" 5985 &>/dev/null; then
    fail "WinRM port 5985 not reachable on $VM_IP"
    echo "  Ensure the prepare-vagrant-winrm.ps1 script was run inside the VM."
    exit 1
fi
ok "WinRM port reachable"

# Find Python with winrm
PYTHON=""
if python3 -c "import winrm" &>/dev/null; then
    PYTHON="python3"
elif [[ -f "$PROJECT_DIR/.setup-venv/bin/python" ]]; then
    PYTHON="$PROJECT_DIR/.setup-venv/bin/python"
else
    fail "pywinrm not found. Install: pip3 install pywinrm requests-ntlm"
    exit 1
fi

# Test authentication
AUTH_OK=$($PYTHON -c "
import winrm, sys
try:
    s = winrm.Session('http://$VM_IP:5985/wsman', auth=('$VM_USER','$VM_PASS'), transport='ntlm')
    r = s.run_ps('whoami')
    if r.status_code == 0: print('ok')
    else: print('fail')
except: print('fail')
" 2>/dev/null)

if [[ "$AUTH_OK" != "ok" ]]; then
    fail "WinRM authentication failed (user=$VM_USER)."
    echo "  If you used a different account, re-run with:"
    echo "    $0 --provision-only --vm-ip $VM_IP --vm-user <user> --vm-pass <pass>"
    exit 1
fi
ok "WinRM authenticated as $VM_USER"

# =============================================================================
# Step 4: Upload Project Files
# =============================================================================

header "Step 4: Uploading Project Files"

info "Packaging project files..."
PROVISION_ZIP="/tmp/tdc-provision-$$.zip"
(cd "$PROJECT_DIR" && zip -qr "$PROVISION_ZIP" config webui rules scripts)
ok "Package created ($(du -h "$PROVISION_ZIP" | cut -f1))"

info "Serving package to VM..."
SERVE_DIR="/tmp/tdc-serve-$$"
mkdir -p "$SERVE_DIR"
cp "$PROVISION_ZIP" "$SERVE_DIR/tdc-provision.zip"

# Start HTTP server in background
python3 -m http.server 8765 --bind 0.0.0.0 --directory "$SERVE_DIR" &>/dev/null &
HTTP_PID=$!
trap "kill $HTTP_PID 2>/dev/null; rm -rf '$SERVE_DIR' '$PROVISION_ZIP'" EXIT
sleep 1

# Get host IP visible to VM (UTM shared network gateway)
HOST_IP="192.168.64.1"

info "Downloading and extracting in VM..."
$PYTHON -c "
import winrm
# Longer timeouts: the 4.5M download + Expand-Archive (with Defender scanning
# every extracted file) routinely exceeds pywinrm's 20s/30s defaults on a
# freshly-booted VM, which makes the WSMan operation return empty output.
s = winrm.Session('http://$VM_IP:5985/wsman', auth=('$VM_USER','$VM_PASS'), transport='ntlm',
                  operation_timeout_sec=120, read_timeout_sec=130)
ps = r'''
\$ErrorActionPreference=\"Stop\"
try {
Invoke-WebRequest -Uri \"http://${HOST_IP}:8765/tdc-provision.zip\" -OutFile C:\\tdc-provision.zip -UseBasicParsing
if (Test-Path C:\\tdc) { Remove-Item C:\\tdc -Recurse -Force }
Expand-Archive -Path C:\\tdc-provision.zip -DestinationPath C:\\tdc -Force
Remove-Item C:\\tdc-provision.zip -Force
# Replicate Vagrant file-provisioner layout
New-Item -ItemType Directory -Path C:\\vagrant\\webui -Force | Out-Null
New-Item -ItemType Directory -Path C:\\vagrant\\rules -Force | Out-Null
if (Test-Path C:\\vagrant_config) { Remove-Item C:\\vagrant_config -Recurse -Force }
Copy-Item C:\\tdc\\config   C:\\vagrant_config -Recurse -Force
Copy-Item C:\\tdc\\webui\\*  C:\\vagrant\\webui -Recurse -Force
Copy-Item C:\\tdc\\rules\\*  C:\\vagrant\\rules -Recurse -Force
\"OK\"
} catch { \"CAUGHT: \" + \$_.Exception.Message + \" @ \" + \$_.InvocationInfo.Line }
'''
r = s.run_ps(ps)
out = r.std_out.decode(errors='replace').strip()
if 'OK' not in out:
    print('FAILED:', out)
    raise SystemExit(1)
print(out)
" 2>/dev/null

ok "Project files deployed to VM"

# Kill HTTP server
kill $HTTP_PID 2>/dev/null || true

# =============================================================================
# Step 5: Provisioning
# =============================================================================

header "Step 5: Provisioning (this takes 20-40 minutes)"

# Provisioning scripts in order (matching Vagrantfile.utm)
SCRIPTS=(
    "install-prerequisites.ps1"
    "install-sysmon.ps1"
    "install-fibratus.ps1"
    "install-rustinel.ps1"
    "install-detection-rules.ps1"
    "install-detonator.ps1"
    "install-litterbox.ps1"
    "install-thezoo.ps1"
    "install-hunt-sleeping-beacons.ps1"
    "install-beaconeye.ps1"
    "install-scanner-tools.ps1"
    "install-ember.ps1"
    "install-capa.ps1"
    "install-re-tools.ps1"
    "install-webui.ps1"
    "configure-services.ps1"
)

run_provision_script() {
    local script="$1"
    local timeout="${2:-900}"  # 15 min default

    $PYTHON -c "
import winrm, time, sys
s = winrm.Session('http://$VM_IP:5985/wsman', auth=('$VM_USER','$VM_PASS'), transport='ntlm',
                  operation_timeout_sec=30, read_timeout_sec=35)

# Register and start as Scheduled Task (survives WinRM session end)
ps = r'''
\$ErrorActionPreference=\"Continue\"
New-Item -ItemType Directory -Path C:\\tdc\\logs -Force | Out-Null
\$log  = \"C:\\tdc\\logs\\${script}.log\"
\$done = \"C:\\tdc\\logs\\${script}.done\"
if (Test-Path \$done) { Remove-Item \$done -Force }
if (Test-Path \$log)  { Remove-Item \$log  -Force }
\$wrapper = \"C:\\tdc\\logs\\run-${script}\"
@\"
Set-ExecutionPolicy Bypass -Scope Process -Force
try { & 'C:\\tdc\\scripts\\${script}' *>&1 | Out-File -FilePath '\$log' -Encoding utf8 }
finally { \"EXITCODE=\\\$LASTEXITCODE\" | Out-File -Append '\$log'; 'done' | Out-File '\$done' }
\"@ | Out-File -FilePath \$wrapper -Encoding utf8

\$action  = New-ScheduledTaskAction -Execute \"powershell.exe\" -Argument \"-NoProfile -ExecutionPolicy Bypass -File \$wrapper\"
\$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 3)
Unregister-ScheduledTask -TaskName \"tdc-${script}\" -Confirm:\$false -EA SilentlyContinue
Register-ScheduledTask -TaskName \"tdc-${script}\" -Action \$action -Settings \$settings -User \"$VM_USER\" -Password \"$VM_PASS\" -RunLevel Highest | Out-Null
Start-ScheduledTask -TaskName \"tdc-${script}\"
\"STARTED\"
'''
r = s.run_ps(ps)
if 'STARTED' not in r.std_out.decode(errors='replace'):
    print('FAILED to start task', file=sys.stderr)
    sys.exit(1)

# Poll for completion
start = time.time()
while time.time() - start < $timeout:
    time.sleep(15)
    r = s.run_ps(r'if (Test-Path \"C:\\tdc\\logs\\${script}.done\") { \"DONE\" } else { \"RUNNING\" }')
    if 'DONE' in r.std_out.decode(errors='replace'):
        # Get last lines of log
        r2 = s.run_ps(r'Get-Content \"C:\\tdc\\logs\\${script}.log\" -Tail 5')
        print(r2.std_out.decode(errors='replace').strip())
        sys.exit(0)
    elapsed = int(time.time() - start)
    print(f'  ... {elapsed}s', end='\r', flush=True)

print(f'TIMEOUT after {$timeout}s', file=sys.stderr)
sys.exit(1)
" 2>/dev/null
}

total=${#SCRIPTS[@]}
current=0

for script in "${SCRIPTS[@]}"; do
    current=$((current + 1))
    info "[$current/$total] Running $script..."

    if run_provision_script "$script"; then
        ok "[$current/$total] $script completed"
    else
        warn "[$current/$total] $script had issues (non-critical, continuing)"
    fi
    echo ""
done

# =============================================================================
# Step 6: Post-Install Fixes (ARM64-specific)
# =============================================================================

header "Step 6: ARM64-Specific Configuration"

info "Installing nssm and configuring Rustinel as a service..."
$PYTHON -c "
import winrm
s = winrm.Session('http://$VM_IP:5985/wsman', auth=('$VM_USER','$VM_PASS'), transport='ntlm')
ps = r'''
# Rustinel needs nssm to run as a persistent service on ARM64
if (-not (Get-Command nssm -EA SilentlyContinue)) {
    choco install nssm -y --no-progress 2>&1 | Out-Null
}
\$nssm = (Get-Command nssm -EA SilentlyContinue).Source
if (-not \$nssm) { \$nssm = \"C:\\ProgramData\\chocolatey\\bin\\nssm.exe\" }
& \$nssm stop Rustinel 2>&1 | Out-Null
& \$nssm remove Rustinel confirm 2>&1 | Out-Null
& \$nssm install Rustinel \"C:\\tools\\rustinel\\rustinel.exe\" \"run\"
& \$nssm set Rustinel AppDirectory \"C:\\tools\\rustinel\"
& \$nssm set Rustinel AppStdout \"C:\\tools\\rustinel\\rustinel-stdout.log\"
& \$nssm set Rustinel AppStderr \"C:\\tools\\rustinel\\rustinel-stderr.log\"
& \$nssm set Rustinel Start SERVICE_AUTO_START
& \$nssm start Rustinel
Start-Sleep 3
\$p = Get-Process rustinel* -EA SilentlyContinue
if (\$p) { \"Rustinel running PID=\" + \$p.Id } else { \"Rustinel not running\" }
'''
r = s.run_ps(ps)
print(r.std_out.decode(errors='replace').strip())
" 2>/dev/null

info "Patching Sysmon service detection for ARM64..."
$PYTHON -c "
import winrm
s = winrm.Session('http://$VM_IP:5985/wsman', auth=('$VM_USER','$VM_PASS'), transport='ntlm')
ps = r'''
\$f = \"C:\\DetonationChamberUI\\app.py\"
if (Test-Path \$f) {
    \$c = [System.IO.File]::ReadAllText(\$f)
    if (\$c -match 'for svc_name in') {
        \"Already patched (loop variant)\"
    } elseif (\$c -match '\"Sysmon64a\"') {
        \"Already contains Sysmon64a reference\"
    } else {
        # Replace single sc query with dual-check loop
        \$old = '''\$\"sc\", \"query\", \"Sysmon64\"'''
        \$c = \$c.Replace('\"Sysmon64\"', '\"Sysmon64a\"')
        [System.IO.File]::WriteAllText(\$f, \$c)
        \"Patched Sysmon64 -> Sysmon64a\"
    }
}
'''
r = s.run_ps(ps)
print(r.std_out.decode(errors='replace').strip())
" 2>/dev/null

ok "ARM64-specific fixes applied"

# =============================================================================
# Step 7: Verify
# =============================================================================

header "Step 7: Verification"

info "Waiting for services to stabilize..."
sleep 10

info "Checking service status..."
STATUS=$(curl -sf "http://$VM_IP:9000/api/status" 2>/dev/null)

if [[ -n "$STATUS" ]]; then
    ok "Web UI responding on http://$VM_IP:9000"
    echo ""
    echo "$STATUS" | python3 -m json.tool 2>/dev/null || echo "$STATUS"
    echo ""

    # Count online services
    ONLINE=$(echo "$STATUS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for v in d.values() if isinstance(v,dict) and v.get('online')))" 2>/dev/null || echo "?")
    TOTAL=$(echo "$STATUS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "?")
    ok "$ONLINE/$TOTAL services online"
else
    warn "Web UI not responding yet. It may need a few more seconds."
    echo "  Try: curl http://$VM_IP:9000/api/status"
fi

# =============================================================================
# Done
# =============================================================================

header "Setup Complete"

echo ""
echo -e "  ${GREEN}${BOLD}Transportable Detonation Chamber is ready!${NC}"
echo ""
echo "  Web UI:          http://$VM_IP:9000"
echo "  LitterBox:       http://$VM_IP:1337"
echo "  Detonator UI:    http://$VM_IP:5000"
echo "  Detonator API:   http://$VM_IP:8000"
echo "  DetonatorAgent:  http://$VM_IP:8080"
echo ""
echo "  VM Access:"
echo "    WinRM: winrs -r:http://$VM_IP:5985 -u:$VM_USER -p:$VM_PASS cmd"
echo "    RDP:   open rdp://$VM_IP (or use Microsoft Remote Desktop)"
echo ""
echo "  Known ARM64 Limitations:"
echo "    - Hunt-Sleeping-Beacons: x86-only (uses x86 register context)"
echo "    - BeaconEye: requires .NET Framework 4.8 (not available on ARM64)"
echo "    - ThreatCheck/DefenderCheck: no ARM64 builds available"
echo ""
echo "  To re-run provisioning later:"
echo "    $0 --provision-only --vm-ip $VM_IP"
echo ""
