#!/usr/bin/env bash
# build-box-macos.sh
# Builds a Windows 11 ARM64 Vagrant box for use with vagrant-qemu on Apple Silicon.
#
# This script:
#   1. Verifies prerequisites (QEMU, swtpm, etc.)
#   2. Locates or prompts for a Windows 11 ARM64 ISO
#   3. Creates an Autounattend.xml for unattended installation
#   4. Boots QEMU with the ISO and installs Windows automatically
#   5. Configures WinRM and vagrant user post-install
#   6. Packages the result as a Vagrant box (win11-arm)
#
# Usage:
#   ./scripts/build-box-macos.sh                     # Interactive (prompts for ISO)
#   ./scripts/build-box-macos.sh --iso ~/Downloads/Win11_ARM64.iso
#   ./scripts/build-box-macos.sh --skip-install      # Package existing disk image
#
# Requirements:
#   - macOS on Apple Silicon (M1/M2/M3/M4)
#   - QEMU:  brew install qemu
#   - swtpm: brew install swtpm  (optional, for TPM 2.0)
#   - ~80 GB free disk space
#
# The Windows 11 ARM64 ISO can be downloaded from:
#   https://www.microsoft.com/software-download/windows11arm64
#
# After building:
#   vagrant box add win11-arm output/win11-arm.box --provider qemu
#   make up   # or: VAGRANT_VAGRANTFILE=Vagrantfile.utm vagrant up --provider=qemu

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/.build-box"
OUTPUT_DIR="$PROJECT_DIR/.build-box/output"
DISK_IMAGE="$BUILD_DIR/win11-arm.qcow2"
DISK_SIZE="80G"
RAM="4096"
CPUS="4"
VM_NAME="win11-arm-builder"
BOX_NAME="win11-arm"

# ISO search locations
ISO_SEARCH_DIRS=(
    "$HOME/Downloads"
    "$HOME/Desktop"
    "$HOME/Documents"
    "$BUILD_DIR"
    "$HOME/.cache/detonation-chamber"
)

# Microsoft download page
WIN11_ARM_URL="https://www.microsoft.com/software-download/windows11arm64"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# CLI Arguments
# =============================================================================

ISO_PATH=""
SKIP_INSTALL=false
SKIP_PACKAGE=false
HEADLESS=true
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --iso)        ISO_PATH="$2"; shift 2 ;;
        --skip-install) SKIP_INSTALL=true; shift ;;
        --skip-package) SKIP_PACKAGE=true; shift ;;
        --gui)        HEADLESS=false; shift ;;
        --force)      FORCE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --iso PATH       Path to Windows 11 ARM64 ISO file"
            echo "  --skip-install   Skip ISO install (package existing disk image)"
            echo "  --skip-package   Only install, don't package as Vagrant box"
            echo "  --gui            Show QEMU display window (default: headless)"
            echo "  --force          Overwrite existing build artifacts"
            echo "  -h, --help       Show this help"
            echo ""
            echo "Download the ISO from:"
            echo "  $WIN11_ARM_URL"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# =============================================================================
# Helper Functions
# =============================================================================

info()    { echo -e "${CYAN}[*]${NC} $1"; }
ok()      { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
fail()    { echo -e "${RED}[-]${NC} $1"; }
header()  { echo -e "\n${BOLD}=== $1 ===${NC}\n"; }

check_command() {
    if command -v "$1" &>/dev/null; then
        return 0
    fi
    return 1
}

wait_for_shutdown() {
    local pid=$1
    local timeout=${2:-7200}  # Default 2 hours for Windows install
    local elapsed=0

    info "Waiting for VM to shut down (timeout: ${timeout}s)..."
    while kill -0 "$pid" 2>/dev/null; do
        sleep 10
        elapsed=$((elapsed + 10))
        if [[ $elapsed -ge $timeout ]]; then
            warn "Timeout reached. Killing QEMU..."
            kill "$pid" 2>/dev/null || true
            return 1
        fi
        # Progress indicator every 60 seconds
        if [[ $((elapsed % 60)) -eq 0 ]]; then
            info "  Still running... (${elapsed}s elapsed)"
        fi
    done
    ok "VM has shut down."
    return 0
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

header "Pre-flight Checks"

# Platform check
if [[ "$(uname -s)" != "Darwin" ]]; then
    fail "This script is for macOS only."
    exit 1
fi
if [[ "$(uname -m)" != "arm64" ]]; then
    fail "Apple Silicon (ARM64) required. Detected: $(uname -m)"
    exit 1
fi
ok "macOS Apple Silicon detected"

# QEMU
if check_command qemu-system-aarch64; then
    ok "QEMU found: $(qemu-system-aarch64 --version | head -1)"
else
    fail "QEMU not installed. Install with: brew install qemu"
    exit 1
fi

# EFI firmware
EFI_CODE=""
for candidate in \
    "/opt/homebrew/share/qemu/edk2-aarch64-code.fd" \
    "/usr/local/share/qemu/edk2-aarch64-code.fd" \
    "$(brew --prefix 2>/dev/null)/share/qemu/edk2-aarch64-code.fd"; do
    if [[ -f "$candidate" ]]; then
        EFI_CODE="$candidate"
        break
    fi
done
if [[ -z "$EFI_CODE" ]]; then
    fail "EFI firmware (edk2-aarch64-code.fd) not found."
    fail "Reinstall QEMU: brew reinstall qemu"
    exit 1
fi
ok "EFI firmware: $EFI_CODE"

# swtpm (optional but recommended for Windows 11)
HAS_SWTPM=false
if check_command swtpm; then
    HAS_SWTPM=true
    ok "swtpm found (TPM 2.0 emulation available)"
else
    warn "swtpm not found. Windows 11 will be installed with TPM requirement bypassed."
    warn "Install swtpm for proper TPM support: brew install swtpm"
fi

# Disk space check
AVAIL_GB=$(df -g "$PROJECT_DIR" | awk 'NR==2 {print $4}')
if [[ "$AVAIL_GB" -lt 80 ]]; then
    fail "Insufficient disk space: ${AVAIL_GB} GB available, 80 GB needed."
    exit 1
fi
ok "Disk space: ${AVAIL_GB} GB available"

# Check if box already exists
if ! $FORCE && vagrant box list 2>/dev/null | grep -q "$BOX_NAME"; then
    warn "Vagrant box '$BOX_NAME' already exists."
    echo ""
    echo "  To rebuild, run with --force:"
    echo "    $0 --force"
    echo ""
    echo "  Or remove the existing box first:"
    echo "    vagrant box remove $BOX_NAME --provider qemu"
    echo ""
    exit 0
fi

# =============================================================================
# Locate Windows 11 ARM64 ISO
# =============================================================================

header "Windows 11 ARM64 ISO"

if [[ -n "$ISO_PATH" ]]; then
    if [[ ! -f "$ISO_PATH" ]]; then
        fail "ISO not found at specified path: $ISO_PATH"
        exit 1
    fi
    ok "Using ISO: $ISO_PATH"
elif ! $SKIP_INSTALL; then
    # Search common locations
    info "Searching for Windows 11 ARM64 ISO..."
    FOUND_ISO=""
    for dir in "${ISO_SEARCH_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            # Look for common ISO naming patterns
            while IFS= read -r -d '' file; do
                FOUND_ISO="$file"
                break
            done < <(find "$dir" -maxdepth 2 \( \
                -iname "*Win11*ARM*iso" -o \
                -iname "*Windows*11*ARM*iso" -o \
                -iname "*Win11*aarch64*iso" -o \
                -iname "*22631*ARM*iso" -o \
                -iname "*26100*ARM*iso" \
            \) -print0 2>/dev/null)
            [[ -n "$FOUND_ISO" ]] && break
        fi
    done

    if [[ -n "$FOUND_ISO" ]]; then
        ok "Found ISO: $FOUND_ISO"
        ISO_PATH="$FOUND_ISO"
    else
        echo ""
        fail "Windows 11 ARM64 ISO not found."
        echo ""
        echo -e "  ${BOLD}Download the ISO from Microsoft:${NC}"
        echo "  $WIN11_ARM_URL"
        echo ""
        echo "  Steps:"
        echo "    1. Open the URL above in your browser"
        echo "    2. Sign in with a Microsoft account (free)"
        echo "    3. Select 'Windows 11' and choose language"
        echo "    4. Click 'Download' (approx. 5-6 GB)"
        echo "    5. Save to ~/Downloads/"
        echo ""
        echo "  Then re-run this script:"
        echo "    $0 --iso ~/Downloads/Win11_<version>_arm64.iso"
        echo ""
        echo "  Or place the ISO in any of these directories and re-run:"
        for dir in "${ISO_SEARCH_DIRS[@]}"; do
            echo "    - $dir"
        done
        echo ""

        # Try to open the download page
        read -p "  Open Microsoft download page in browser? [Y/n] " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            open "$WIN11_ARM_URL" 2>/dev/null || true
            echo ""
            info "Download the ISO, then re-run:"
            echo "    $0 --iso /path/to/downloaded.iso"
        fi
        exit 1
    fi
fi

# =============================================================================
# Create Build Directory
# =============================================================================

header "Build Setup"

mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"
info "Build directory: $BUILD_DIR"

# Create EFI vars file (writable NVRAM for Windows)
EFI_VARS="$BUILD_DIR/efivars.fd"
if [[ ! -f "$EFI_VARS" ]] || $FORCE; then
    info "Creating EFI variable store (64 MB)..."
    dd if=/dev/zero of="$EFI_VARS" bs=1m count=64 2>/dev/null
    ok "EFI vars: $EFI_VARS"
fi

# =============================================================================
# Create Autounattend.xml
# =============================================================================

if ! $SKIP_INSTALL; then

header "Creating Autounattend.xml"

# This XML performs a fully unattended Windows 11 ARM64 installation:
# - Bypasses TPM, Secure Boot, RAM, and CPU checks
# - Creates 'vagrant' user with password 'vagrant' (administrator)
# - Enables WinRM for remote management
# - Enables RDP
# - Disables Windows Defender real-time protection
# - Sets up auto-login

AUTOUNATTEND="$BUILD_DIR/Autounattend.xml"
cat > "$AUTOUNATTEND" << 'XMLEOF'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">

  <!-- Pass 1: windowsPE - Disk setup and install source -->
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE"
               processorArchitecture="arm64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <SetupUILanguage>
        <UILanguage>en-US</UILanguage>
      </SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>

    <component name="Microsoft-Windows-Setup"
               processorArchitecture="arm64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

      <!-- Bypass Windows 11 hardware requirements -->
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>3</Order>
          <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>4</Order>
          <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassCPUCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
      </RunSynchronous>

      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <!-- EFI System Partition -->
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Size>260</Size>
              <Type>EFI</Type>
            </CreatePartition>
            <!-- MSR -->
            <CreatePartition wcm:action="add">
              <Order>2</Order>
              <Size>16</Size>
              <Type>MSR</Type>
            </CreatePartition>
            <!-- Windows -->
            <CreatePartition wcm:action="add">
              <Order>3</Order>
              <Extend>true</Extend>
              <Type>Primary</Type>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Format>FAT32</Format>
              <Label>EFI</Label>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order>
              <PartitionID>3</PartitionID>
              <Format>NTFS</Format>
              <Label>Windows</Label>
              <Letter>C</Letter>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>

      <ImageInstall>
        <OSImage>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>3</PartitionID>
          </InstallTo>
          <!-- Use the Pro edition (index may vary; 1=Home, 3=Pro typically for ARM) -->
          <InstallFrom>
            <MetaData wcm:action="add">
              <Key>/IMAGE/NAME</Key>
              <Value>Windows 11 Pro</Value>
            </MetaData>
          </InstallFrom>
        </OSImage>
      </ImageInstall>

      <UserData>
        <AcceptEula>true</AcceptEula>
        <ProductKey>
          <!-- Generic Windows 11 Pro key (for installation only, not activation) -->
          <Key>VK7JG-NPHTM-C97JM-9MPGT-3V66T</Key>
        </ProductKey>
      </UserData>
    </component>
  </settings>

  <!-- Pass 4: specialize - Computer name and network -->
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup"
               processorArchitecture="arm64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <ComputerName>detonation-chamber</ComputerName>
    </component>

    <!-- Skip network-based OOBE (Microsoft account requirement bypass) -->
    <component name="Microsoft-Windows-Deployment"
               processorArchitecture="arm64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v BypassNRO /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>

  <!-- Pass 7: oobeSystem - User account and first-boot settings -->
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup"
               processorArchitecture="arm64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <NetworkLocation>Work</NetworkLocation>
        <ProtectYourPC>3</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>

      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>vagrant</Name>
            <DisplayName>vagrant</DisplayName>
            <Group>Administrators</Group>
            <Password>
              <Value>vagrant</Value>
              <PlainText>true</PlainText>
            </Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>

      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>vagrant</Username>
        <Password>
          <Value>vagrant</Value>
          <PlainText>true</PlainText>
        </Password>
        <LogonCount>3</LogonCount>
      </AutoLogon>

      <!-- First-logon commands: configure WinRM, RDP, firewall -->
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
          <Description>Disable firewall for initial setup</Description>
        </SynchronousCommand>

        <SynchronousCommand wcm:action="add">
          <Order>2</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "Enable-PSRemoting -Force -SkipNetworkProfileCheck"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
          <Description>Enable PowerShell remoting</Description>
        </SynchronousCommand>

        <SynchronousCommand wcm:action="add">
          <Order>3</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "winrm quickconfig -force; winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'; winrm set winrm/config/service/auth '@{Basic=\"true\"}'; winrm set winrm/config/client '@{AllowUnencrypted=\"true\"}'; winrm set winrm/config '@{MaxTimeoutms=\"1800000\"}';"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
          <Description>Configure WinRM for Vagrant</Description>
        </SynchronousCommand>

        <SynchronousCommand wcm:action="add">
          <Order>4</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord -Force"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
          <Description>Allow remote admin for local accounts</Description>
        </SynchronousCommand>

        <SynchronousCommand wcm:action="add">
          <Order>5</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -Force; Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
          <Description>Enable RDP</Description>
        </SynchronousCommand>

        <SynchronousCommand wcm:action="add">
          <Order>6</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue; Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
          <Description>Disable Windows Defender real-time (for malware detonation)</Description>
        </SynchronousCommand>

        <SynchronousCommand wcm:action="add">
          <Order>7</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-Service -Name WinRM -StartupType Automatic; Start-Service WinRM"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
          <Description>Ensure WinRM starts on boot</Description>
        </SynchronousCommand>

        <SynchronousCommand wcm:action="add">
          <Order>8</Order>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "netsh advfirewall firewall add rule name='WinRM-HTTP' dir=in localport=5985 protocol=tcp action=allow"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
          <Description>Allow WinRM through firewall</Description>
        </SynchronousCommand>

        <!-- Auto-shutdown after setup to signal completion -->
        <SynchronousCommand wcm:action="add">
          <Order>9</Order>
          <CommandLine>cmd /c shutdown /s /t 60 /f /c "Windows setup complete - shutting down for packaging"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
          <Description>Shutdown for Vagrant box packaging</Description>
        </SynchronousCommand>
      </FirstLogonCommands>

      <TimeZone>UTC</TimeZone>
    </component>

    <component name="Microsoft-Windows-International-Core"
               processorArchitecture="arm64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
  </settings>
</unattend>
XMLEOF

ok "Autounattend.xml created"

# =============================================================================
# Create VirtIO driver ISO (if available)
# =============================================================================

# Check for VirtIO drivers - needed for disk/network during Windows install
VIRTIO_ISO=""
VIRTIO_CANDIDATES=(
    "$BUILD_DIR/virtio-win.iso"
    "$HOME/Downloads/virtio-win.iso"
    "/opt/homebrew/share/virtio-win/virtio-win.iso"
)
for candidate in "${VIRTIO_CANDIDATES[@]}"; do
    if [[ -f "$candidate" ]]; then
        VIRTIO_ISO="$candidate"
        break
    fi
done

if [[ -z "$VIRTIO_ISO" ]]; then
    info "Downloading VirtIO drivers ISO (needed for disk/network in QEMU)..."
    VIRTIO_ISO="$BUILD_DIR/virtio-win.iso"
    # Latest stable VirtIO drivers from Fedora
    VIRTIO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
    if curl -fSL --progress-bar -o "$VIRTIO_ISO" "$VIRTIO_URL"; then
        ok "VirtIO drivers downloaded: $VIRTIO_ISO"
    else
        warn "VirtIO ISO download failed. Windows may not detect the disk during install."
        warn "You may need to use IDE disk interface instead of virtio."
        warn "Download manually from: $VIRTIO_URL"
        VIRTIO_ISO=""
    fi
fi

# =============================================================================
# Create Answer File ISO (contains Autounattend.xml)
# =============================================================================

info "Creating answer file ISO..."
ANSWER_DIR="$BUILD_DIR/answer-files"
ANSWER_ISO="$BUILD_DIR/answer.iso"
mkdir -p "$ANSWER_DIR"
cp "$AUTOUNATTEND" "$ANSWER_DIR/Autounattend.xml"

# Create ISO using hdiutil (macOS native)
hdiutil makehybrid -o "$ANSWER_ISO" "$ANSWER_DIR" \
    -iso -joliet -default-volume-name "OEMDRV" \
    -quiet 2>/dev/null || {
    # Fallback: try mkisofs/genisoimage
    if check_command mkisofs; then
        mkisofs -quiet -o "$ANSWER_ISO" -J -r -V "OEMDRV" "$ANSWER_DIR"
    elif check_command genisoimage; then
        genisoimage -quiet -o "$ANSWER_ISO" -J -r -V "OEMDRV" "$ANSWER_DIR"
    else
        fail "Cannot create ISO. Install cdrtools: brew install cdrtools"
        exit 1
    fi
}
ok "Answer ISO created: $ANSWER_ISO"

# =============================================================================
# Create Disk Image
# =============================================================================

if [[ -f "$DISK_IMAGE" ]] && ! $FORCE; then
    warn "Disk image already exists: $DISK_IMAGE"
    warn "Use --force to overwrite, or --skip-install to package existing image."
else
    info "Creating QCOW2 disk image (${DISK_SIZE})..."
    qemu-img create -f qcow2 "$DISK_IMAGE" "$DISK_SIZE"
    ok "Disk image: $DISK_IMAGE"
fi

# =============================================================================
# Start TPM Emulator (if available)
# =============================================================================

TPM_DIR="$BUILD_DIR/tpm"
SWTPM_PID=""
TPM_ARGS=""

if $HAS_SWTPM; then
    info "Starting TPM 2.0 emulator (swtpm)..."
    mkdir -p "$TPM_DIR"
    swtpm socket \
        --tpmstate dir="$TPM_DIR" \
        --ctrl type=unixio,path="$TPM_DIR/swtpm-sock" \
        --tpm2 \
        --daemon \
        --log file="$BUILD_DIR/swtpm.log"
    SWTPM_PID=$(pgrep -f "swtpm.*$TPM_DIR" | head -1)
    ok "swtpm running (PID: ${SWTPM_PID:-unknown})"

    TPM_ARGS="-chardev socket,id=chrtpm,path=$TPM_DIR/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0"
fi

# Cleanup function
cleanup() {
    if [[ -n "$SWTPM_PID" ]]; then
        kill "$SWTPM_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# =============================================================================
# Install Windows 11 ARM64
# =============================================================================

header "Installing Windows 11 ARM64"

echo "  ISO:      $ISO_PATH"
echo "  Disk:     $DISK_IMAGE"
echo "  RAM:      ${RAM} MB"
echo "  CPUs:     $CPUS"
echo "  VirtIO:   ${VIRTIO_ISO:-none}"
echo "  TPM:      $(if $HAS_SWTPM; then echo 'yes (swtpm)'; else echo 'no (bypassed via registry)'; fi)"
echo "  Headless: $HEADLESS"
echo ""
info "Starting Windows installation. This takes 20-40 minutes..."
info "The VM will shut down automatically when installation is complete."
echo ""

# Build QEMU command
DISPLAY_ARG=""
if $HEADLESS; then
    DISPLAY_ARG="-display none"
else
    DISPLAY_ARG="-display cocoa"
fi

VIRTIO_DRIVE_ARGS=""
if [[ -n "$VIRTIO_ISO" ]]; then
    VIRTIO_DRIVE_ARGS="-drive file=$VIRTIO_ISO,media=cdrom,if=none,id=virtiocd -device usb-storage,drive=virtiocd"
fi

# Launch QEMU
qemu-system-aarch64 \
    -name "$VM_NAME" \
    -machine virt,highmem=on \
    -accel hvf \
    -cpu host \
    -smp cpus=$CPUS,sockets=1,cores=$CPUS,threads=1 \
    -m $RAM \
    -drive if=pflash,format=raw,readonly=on,file="$EFI_CODE" \
    -drive if=pflash,format=raw,file="$EFI_VARS" \
    -drive if=virtio,file="$DISK_IMAGE",format=qcow2,cache=writeback \
    -drive file="$ISO_PATH",media=cdrom,if=none,id=installcd \
    -device usb-storage,drive=installcd \
    -drive file="$ANSWER_ISO",media=cdrom,if=none,id=answercd \
    -device usb-storage,drive=answercd \
    $VIRTIO_DRIVE_ARGS \
    -device virtio-gpu-pci \
    -device qemu-xhci \
    -device usb-kbd \
    -device usb-tablet \
    -device virtio-net-pci,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::15985-:5985 \
    $TPM_ARGS \
    $DISPLAY_ARG \
    -serial null \
    -daemonize \
    -pidfile "$BUILD_DIR/qemu.pid" \
    || { fail "Failed to start QEMU"; exit 1; }

QEMU_PID=$(cat "$BUILD_DIR/qemu.pid" 2>/dev/null)
ok "QEMU started (PID: $QEMU_PID)"
info "Windows is installing. Monitor progress:"
if $HEADLESS; then
    echo "    Re-run with --gui flag to see the display"
else
    echo "    A QEMU window should have appeared"
fi
echo ""
echo "    To check if it's still running:"
echo "      ps -p $QEMU_PID"
echo ""
echo "    To force-stop if stuck:"
echo "      kill $QEMU_PID"
echo ""

# Wait for VM to shut down (Windows auto-shuts down after setup)
if ! wait_for_shutdown "$QEMU_PID" 7200; then
    fail "Installation timed out or was interrupted."
    fail "Check if Windows installed correctly by re-running with --gui"
    exit 1
fi

ok "Windows 11 ARM64 installation complete!"

fi # end !$SKIP_INSTALL

# =============================================================================
# Verify Disk Image
# =============================================================================

if [[ ! -f "$DISK_IMAGE" ]]; then
    fail "Disk image not found: $DISK_IMAGE"
    fail "Run without --skip-install to perform the installation first."
    exit 1
fi

DISK_SIZE_ACTUAL=$(du -h "$DISK_IMAGE" | cut -f1)
ok "Disk image: $DISK_IMAGE ($DISK_SIZE_ACTUAL)"

# =============================================================================
# Package as Vagrant Box
# =============================================================================

if $SKIP_PACKAGE; then
    ok "Skipping packaging (--skip-package). Disk image is ready."
    echo "  Image: $DISK_IMAGE"
    echo ""
    echo "  To package manually:"
    echo "    $0 --skip-install"
    exit 0
fi

header "Packaging Vagrant Box"

BOX_FILE="$OUTPUT_DIR/${BOX_NAME}.box"

# Create Vagrantfile for the box (embedded metadata)
EMBEDDED_VAGRANTFILE="$BUILD_DIR/box-Vagrantfile"
cat > "$EMBEDDED_VAGRANTFILE" << 'VFEOF'
# Embedded Vagrantfile for win11-arm box
Vagrant.configure("2") do |config|
  config.vm.communicator = "winrm"
  config.winrm.username = "vagrant"
  config.winrm.password = "vagrant"
  config.winrm.transport = :plaintext
  config.winrm.basic_auth_only = true

  config.vm.provider "qemu" do |qe|
    qe.arch = "aarch64"
    qe.machine = "virt,highmem=on"
    qe.cpu = "host"
    qe.accel = "hvf"
    qe.net_device = "virtio-net-pci"
    qe.drive_interface = "virtio"
  end
end
VFEOF

# Create metadata.json
METADATA="$BUILD_DIR/metadata.json"
cat > "$METADATA" << EOF
{
  "provider": "qemu",
  "format": "qcow2",
  "virtual_size": 80
}
EOF

# Create info.json (optional, for display)
INFO="$BUILD_DIR/info.json"
cat > "$INFO" << EOF
{
  "name": "$BOX_NAME",
  "description": "Windows 11 ARM64 for Transportable Detonation Chamber",
  "versions": [{
    "version": "1.0.0",
    "providers": [{
      "name": "qemu",
      "architecture": "arm64"
    }]
  }]
}
EOF

info "Creating box archive (this may take a few minutes)..."

# Compact the QCOW2 image first
info "Compacting disk image..."
qemu-img convert -O qcow2 -c "$DISK_IMAGE" "$BUILD_DIR/box.img"
ok "Compacted image: $(du -h "$BUILD_DIR/box.img" | cut -f1)"

# Package everything into a .box file (tar archive)
pushd "$BUILD_DIR" > /dev/null
tar -czf "$BOX_FILE" \
    -s '/box.img/box.img/' \
    box.img \
    -s "/box-Vagrantfile/Vagrantfile/" \
    box-Vagrantfile \
    metadata.json
popd > /dev/null

# Clean up temp image
rm -f "$BUILD_DIR/box.img"

BOX_SIZE=$(du -h "$BOX_FILE" | cut -f1)
ok "Box created: $BOX_FILE ($BOX_SIZE)"

# =============================================================================
# Import Box into Vagrant
# =============================================================================

header "Importing Vagrant Box"

# Remove existing box if --force
if $FORCE && vagrant box list 2>/dev/null | grep -q "$BOX_NAME"; then
    info "Removing existing '$BOX_NAME' box..."
    vagrant box remove "$BOX_NAME" --provider qemu --force 2>/dev/null || true
fi

info "Importing box as '$BOX_NAME'..."
vagrant box add "$BOX_NAME" "$BOX_FILE" --provider qemu --force
ok "Box '$BOX_NAME' imported successfully!"

# =============================================================================
# Done
# =============================================================================

header "Build Complete"

echo ""
echo -e "  ${GREEN}${BOLD}Windows 11 ARM64 Vagrant box is ready!${NC}"
echo ""
echo "  Box name:  $BOX_NAME"
echo "  Box file:  $BOX_FILE ($BOX_SIZE)"
echo "  Provider:  qemu (vagrant-qemu)"
echo ""
echo "  Next steps:"
echo "    cd $PROJECT_DIR"
echo "    make up            # Start the Detonation Chamber VM"
echo "    make status        # Check service health"
echo "    make open          # Open the Web UI"
echo ""
echo "  Or manually:"
echo "    VAGRANT_VAGRANTFILE=Vagrantfile.utm vagrant up --provider=qemu"
echo ""
echo "  To clean build artifacts:"
echo "    rm -rf $BUILD_DIR"
echo ""
