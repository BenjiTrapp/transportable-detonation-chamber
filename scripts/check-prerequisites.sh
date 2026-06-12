#!/usr/bin/env bash
# check-prerequisites.sh
# Checks and installs all prerequisites for the Transportable Detonation Chamber
# on macOS with Apple Silicon (UTM/QEMU provider)
#
# Usage:
#   ./scripts/check-prerequisites.sh          # Check only
#   ./scripts/check-prerequisites.sh --fix    # Check and auto-install missing dependencies
#
# Prerequisites checked:
#   1. macOS on Apple Silicon (M1/M2/M3/M4)
#   2. Homebrew
#   3. QEMU (with EFI firmware)
#   4. Vagrant
#   5. vagrant-qemu plugin
#   6. Windows 11 ARM64 box (win11-arm)
#   7. Sufficient disk space (80 GB)
#   8. Sufficient RAM (16 GB recommended, 8 GB minimum)

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Globals ---
FIX_MODE=false
ERRORS=0
WARNINGS=0

if [[ "${1:-}" == "--fix" || "${1:-}" == "-f" ]]; then
    FIX_MODE=true
fi

# --- Helpers ---
info()    { echo -e "${CYAN}[*]${NC} $1"; }
ok()      { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; ((WARNINGS++)); }
fail()    { echo -e "${RED}[-]${NC} $1"; ((ERRORS++)); }
header()  { echo -e "\n${BOLD}--- $1 ---${NC}"; }

# --- ISO download helper ---
WIN11_ISO_DIR="$HOME/.cache/detonation-chamber"
WIN11_ISO_NAME="Win11_ARM64.iso"
WIN11_ISO_PATH="$WIN11_ISO_DIR/$WIN11_ISO_NAME"
# Microsoft's UUP dump or direct download URL for Windows 11 ARM64 evaluation
# Note: Microsoft doesn't provide a direct stable URL for ARM64 ISOs.
# Users need to get it from: https://www.microsoft.com/software-download/windows11arm64
# or via UUP dump: https://uupdump.net/
WIN11_DOWNLOAD_PAGE="https://www.microsoft.com/software-download/windows11arm64"

# ============================================================================
header "Platform Detection"
# ============================================================================

# Check macOS
if [[ "$(uname -s)" != "Darwin" ]]; then
    fail "This script is for macOS. On Windows, use: .\\scripts\\check-prerequisites.ps1"
    exit 1
fi
ok "macOS detected"

# Check Apple Silicon
ARCH=$(uname -m)
if [[ "$ARCH" != "arm64" ]]; then
    fail "Apple Silicon (ARM64) required. Detected: $ARCH"
    fail "The UTM/QEMU setup requires an M1/M2/M3/M4 Mac"
    exit 1
fi
ok "Apple Silicon ($ARCH) detected"

# ============================================================================
header "Homebrew"
# ============================================================================

if command -v brew &>/dev/null; then
    BREW_VERSION=$(brew --version | head -1)
    ok "Homebrew installed ($BREW_VERSION)"
else
    fail "Homebrew not installed"
    if $FIX_MODE; then
        info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        eval "$(/opt/homebrew/bin/brew shellenv)"
        ok "Homebrew installed"
        ((ERRORS--))
    else
        info "Install with: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    fi
fi

# ============================================================================
header "QEMU"
# ============================================================================

if command -v qemu-system-aarch64 &>/dev/null; then
    QEMU_VERSION=$(qemu-system-aarch64 --version | head -1)
    ok "QEMU installed ($QEMU_VERSION)"
else
    fail "QEMU not installed"
    if $FIX_MODE; then
        info "Installing QEMU via Homebrew..."
        brew install qemu
        ok "QEMU installed"
        ((ERRORS--))
    else
        info "Install with: brew install qemu"
    fi
fi

# Check EFI firmware
EFI_PATH="/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
if [[ -f "$EFI_PATH" ]]; then
    ok "EFI firmware found: $EFI_PATH"
else
    # Try alternate locations
    ALT_EFI="/usr/local/share/qemu/edk2-aarch64-code.fd"
    if [[ -f "$ALT_EFI" ]]; then
        ok "EFI firmware found: $ALT_EFI"
        warn "EFI firmware is at $ALT_EFI, but Vagrantfile.utm expects $EFI_PATH"
        info "You may need to update Vagrantfile.utm or create a symlink"
    else
        fail "EFI firmware not found at $EFI_PATH"
        if $FIX_MODE; then
            info "Reinstalling QEMU to ensure firmware files are present..."
            brew reinstall qemu
            if [[ -f "$EFI_PATH" ]]; then
                ok "EFI firmware now available"
                ((ERRORS--))
            else
                fail "EFI firmware still not found after reinstall"
            fi
        else
            info "This should be installed with QEMU. Try: brew reinstall qemu"
        fi
    fi
fi

# ============================================================================
header "Vagrant"
# ============================================================================

if command -v vagrant &>/dev/null; then
    VAGRANT_VERSION=$(vagrant --version)
    ok "Vagrant installed ($VAGRANT_VERSION)"
else
    fail "Vagrant not installed"
    if $FIX_MODE; then
        info "Installing Vagrant via Homebrew..."
        brew install --cask vagrant
        ok "Vagrant installed"
        ((ERRORS--))
    else
        info "Install with: brew install --cask vagrant"
    fi
fi

# Check vagrant-qemu plugin
if command -v vagrant &>/dev/null; then
    if vagrant plugin list 2>/dev/null | grep -q "vagrant-qemu"; then
        PLUGIN_VERSION=$(vagrant plugin list 2>/dev/null | grep "vagrant-qemu" | awk '{print $2}')
        ok "vagrant-qemu plugin installed $PLUGIN_VERSION"
    else
        fail "vagrant-qemu plugin not installed"
        if $FIX_MODE; then
            info "Installing vagrant-qemu plugin..."
            vagrant plugin install vagrant-qemu
            ok "vagrant-qemu plugin installed"
            ((ERRORS--))
        else
            info "Install with: vagrant plugin install vagrant-qemu"
        fi
    fi
fi

# ============================================================================
header "Windows 11 ARM64 Vagrant Box"
# ============================================================================

if command -v vagrant &>/dev/null; then
    if vagrant box list 2>/dev/null | grep -q "win11-arm"; then
        BOX_INFO=$(vagrant box list 2>/dev/null | grep "win11-arm")
        ok "win11-arm box found: $BOX_INFO"
    else
        fail "win11-arm Vagrant box not found"
        echo ""
        info "A Windows 11 ARM64 Vagrant box is required. Options:"
        echo ""
        echo "  Option A - Download ISO and build with Packer (recommended):"
        echo "    1. Download Windows 11 ARM64 ISO from:"
        echo "       $WIN11_DOWNLOAD_PAGE"
        echo "    2. Use this script with --fix to set up the Packer build"
        echo ""
        echo "  Option B - Import a pre-built .box file:"
        echo "    vagrant box add win11-arm /path/to/windows11-arm.box --provider qemu"
        echo ""
        echo "  Option C - Create manually in UTM, then package:"
        echo "    1. Create Windows 11 ARM VM in UTM"
        echo "    2. Install & configure WinRM:"
        echo "       winrm quickconfig -force"
        echo "       winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'"
        echo "       winrm set winrm/config/service/auth '@{Basic=\"true\"}'"
        echo "    3. Create vagrant user (password: vagrant) with admin rights"
        echo "    4. Export QCOW2 and package:"
        echo "       vagrant package --base <vm-name> --output win11-arm.box"
        echo ""

        if $FIX_MODE; then
            echo ""
            info "Checking for Windows 11 ARM64 ISO..."
            mkdir -p "$WIN11_ISO_DIR"

            if [[ -f "$WIN11_ISO_PATH" ]]; then
                ok "ISO already downloaded: $WIN11_ISO_PATH"
            else
                # Check if user has an ISO anywhere obvious
                FOUND_ISO=""
                for search_dir in "$HOME/Downloads" "$HOME/Desktop" "$HOME/Documents"; do
                    if [[ -d "$search_dir" ]]; then
                        found=$(find "$search_dir" -maxdepth 2 -iname "*win*11*arm*iso" -o -iname "*windows*11*arm*iso" 2>/dev/null | head -1)
                        if [[ -n "$found" ]]; then
                            FOUND_ISO="$found"
                            break
                        fi
                    fi
                done

                if [[ -n "$FOUND_ISO" ]]; then
                    info "Found existing ISO: $FOUND_ISO"
                    info "Copying to cache directory..."
                    cp "$FOUND_ISO" "$WIN11_ISO_PATH"
                    ok "ISO cached at: $WIN11_ISO_PATH"
                else
                    warn "No Windows 11 ARM64 ISO found locally."
                    echo ""
                    echo "  Microsoft requires manual download (no direct URL available)."
                    echo "  Please download from: $WIN11_DOWNLOAD_PAGE"
                    echo ""
                    echo "  After downloading, either:"
                    echo "    - Place it in ~/Downloads/ and re-run this script with --fix"
                    echo "    - Or copy it to: $WIN11_ISO_PATH"
                    echo ""

                    # Attempt to open the download page in the browser
                    info "Opening Microsoft download page in browser..."
                    open "$WIN11_DOWNLOAD_PAGE" 2>/dev/null || true
                fi
            fi

            # If we have the ISO, offer to set up Packer
            if [[ -f "$WIN11_ISO_PATH" ]]; then
                echo ""
                info "ISO available. Setting up Packer build environment..."

                # Check for Packer
                if ! command -v packer &>/dev/null; then
                    info "Installing Packer via Homebrew..."
                    brew install hashicorp/tap/packer
                fi

                # Create a minimal Packer template for Windows 11 ARM64
                PACKER_DIR="$WIN11_ISO_DIR/packer-win11-arm"
                mkdir -p "$PACKER_DIR"

                if [[ ! -f "$PACKER_DIR/win11-arm.pkr.hcl" ]]; then
                    cat > "$PACKER_DIR/win11-arm.pkr.hcl" << 'PACKER_EOF'
# Packer template for Windows 11 ARM64 Vagrant box (QEMU provider)
# This creates a minimal Windows 11 ARM64 box with WinRM enabled
#
# Usage:
#   cd ~/.cache/detonation-chamber/packer-win11-arm
#   packer init .
#   packer build .
#   vagrant box add win11-arm output/win11-arm.box --provider qemu

packer {
  required_plugins {
    qemu = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "iso_path" {
  type    = string
  default = "../Win11_ARM64.iso"
}

variable "output_dir" {
  type    = string
  default = "output"
}

source "qemu" "win11-arm" {
  iso_url          = var.iso_path
  iso_checksum     = "none"
  output_directory = var.output_dir
  vm_name          = "win11-arm.qcow2"

  accelerator  = "hvf"
  machine_type = "virt,highmem=on"
  cpu_type     = "host"

  memory   = 4096
  cpus     = 4
  disk_size = "80G"

  qemu_binary  = "qemu-system-aarch64"
  qemuargs = [
    ["-bios", "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"],
    ["-device", "virtio-gpu-pci"],
    ["-device", "qemu-xhci"],
    ["-device", "usb-kbd"],
    ["-device", "usb-tablet"],
    ["-drive", "file=${var.iso_path},media=cdrom,if=none,id=cdrom0"],
    ["-device", "usb-storage,drive=cdrom0"],
  ]

  communicator = "winrm"
  winrm_username = "vagrant"
  winrm_password = "vagrant"
  winrm_timeout  = "60m"

  boot_wait = "5s"
  shutdown_command = "shutdown /s /t 10 /f"
}

build {
  sources = ["source.qemu.win11-arm"]

  # Enable WinRM and configure vagrant user
  provisioner "powershell" {
    inline = [
      "Set-ExecutionPolicy Bypass -Scope Process -Force",
      "winrm quickconfig -force",
      "winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'",
      "winrm set winrm/config/service/auth '@{Basic=\"true\"}'",
      "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Force",
    ]
  }

  post-processor "vagrant" {
    output = "${var.output_dir}/win11-arm.box"
    vagrantfile_template = null
    provider_override = "qemu"
  }
}
PACKER_EOF
                    ok "Packer template created at: $PACKER_DIR/win11-arm.pkr.hcl"
                    echo ""
                    info "To build the box:"
                    echo "  cd $PACKER_DIR"
                    echo "  packer init ."
                    echo "  packer build ."
                    echo "  vagrant box add win11-arm output/win11-arm.box --provider qemu"
                    echo ""
                    warn "NOTE: Windows 11 ARM64 ISO requires manual interaction during install."
                    info "For a fully automated build, you need an Autounattend.xml file."
                    info "See: https://github.com/StefanScherer/packer-windows for reference templates."
                else
                    ok "Packer template already exists at: $PACKER_DIR/win11-arm.pkr.hcl"
                fi
            fi
        fi
    fi
fi

# ============================================================================
header "System Resources"
# ============================================================================

# Check available disk space
DISK_AVAIL_GB=$(df -g . | awk 'NR==2 {print $4}')
if [[ "$DISK_AVAIL_GB" -ge 80 ]]; then
    ok "Disk space: ${DISK_AVAIL_GB} GB available (80 GB needed)"
elif [[ "$DISK_AVAIL_GB" -ge 40 ]]; then
    warn "Disk space: ${DISK_AVAIL_GB} GB available (80 GB recommended, may be tight)"
else
    fail "Disk space: ${DISK_AVAIL_GB} GB available (80 GB needed for VM disk)"
fi

# Check RAM
TOTAL_RAM_GB=$(( $(sysctl -n hw.memsize) / 1073741824 ))
if [[ "$TOTAL_RAM_GB" -ge 16 ]]; then
    ok "RAM: ${TOTAL_RAM_GB} GB total (8 GB allocated to VM)"
elif [[ "$TOTAL_RAM_GB" -ge 8 ]]; then
    warn "RAM: ${TOTAL_RAM_GB} GB total (8 GB allocated to VM - this leaves little for macOS)"
    info "Consider reducing VM memory in Vagrantfile.utm if you experience issues"
else
    fail "RAM: ${TOTAL_RAM_GB} GB total (minimum 8 GB needed, 16 GB recommended)"
fi

# ============================================================================
header "Project Files"
# ============================================================================

# Check that required directories exist
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

REQUIRED_DIRS=("config" "webui" "rules" "scripts")
for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        ok "Directory exists: $dir/"
    else
        fail "Missing directory: $dir/"
    fi
done

# Check key files
REQUIRED_FILES=(
    "Vagrantfile.utm"
    "config/rustinel-config.toml"
    "config/fibratus.yml"
    "webui/app.py"
    "webui/requirements.txt"
)
for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$PROJECT_DIR/$file" ]]; then
        ok "File exists: $file"
    else
        fail "Missing file: $file"
    fi
done

# Check rules directory has content
SIGMA_COUNT=$(find "$PROJECT_DIR/rules/sigma" -name "*.yml" 2>/dev/null | wc -l | tr -d ' ')
YARA_COUNT=$(find "$PROJECT_DIR/rules/yara" -name "*.yar" 2>/dev/null | wc -l | tr -d ' ')
if [[ "$SIGMA_COUNT" -gt 0 ]]; then
    ok "Sigma rules: $SIGMA_COUNT files"
else
    warn "No Sigma rules found in rules/sigma/"
fi
if [[ "$YARA_COUNT" -gt 0 ]]; then
    ok "YARA rules: $YARA_COUNT files"
else
    warn "No YARA rules found in rules/yara/"
fi

# ============================================================================
header "Summary"
# ============================================================================

echo ""
if [[ $ERRORS -eq 0 && $WARNINGS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All prerequisites met! Ready to run:${NC}"
    echo "  make up"
    echo "  # or: VAGRANT_VAGRANTFILE=Vagrantfile.utm vagrant up --provider=qemu"
elif [[ $ERRORS -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}Prerequisites met with $WARNINGS warning(s).${NC}"
    echo "You can proceed, but review the warnings above."
    echo ""
    echo "  make up"
else
    echo -e "${RED}${BOLD}$ERRORS error(s) and $WARNINGS warning(s) found.${NC}"
    if ! $FIX_MODE; then
        echo ""
        echo "Run with --fix to auto-install missing dependencies:"
        echo "  ./scripts/check-prerequisites.sh --fix"
    fi
fi
echo ""

exit $ERRORS
