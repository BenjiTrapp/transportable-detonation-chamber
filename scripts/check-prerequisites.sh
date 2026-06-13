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
ALT_EFI="/usr/local/share/qemu/edk2-aarch64-code.fd"
if [[ -f "$EFI_PATH" ]]; then
    ok "EFI firmware found: $EFI_PATH"
elif [[ -f "$ALT_EFI" ]]; then
    ok "EFI firmware found: $ALT_EFI"
    # Vagrantfile.utm auto-detects both locations now
else
    fail "EFI firmware not found"
    if $FIX_MODE; then
        info "Reinstalling QEMU to ensure firmware files are present..."
        brew reinstall qemu
        if [[ -f "$EFI_PATH" ]] || [[ -f "$ALT_EFI" ]]; then
            ok "EFI firmware now available"
            ((ERRORS--))
        else
            fail "EFI firmware still not found after reinstall"
        fi
    else
        info "This should be installed with QEMU. Try: brew reinstall qemu"
    fi
fi

# Check swtpm (TPM 2.0 emulator - optional but recommended)
if command -v swtpm &>/dev/null; then
    ok "swtpm found (TPM 2.0 emulation)"
else
    warn "swtpm not found (optional - Windows 11 TPM requirement will be bypassed)"
    if $FIX_MODE; then
        info "Installing swtpm via Homebrew..."
        brew install swtpm
        if command -v swtpm &>/dev/null; then
            ok "swtpm installed"
            ((WARNINGS--))
        fi
    else
        info "Install with: brew install swtpm"
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
        info "A Windows 11 ARM64 Vagrant box is required."
        echo ""
        echo "  ${BOLD}Recommended: Use the automated box builder:${NC}"
        echo "    ./scripts/build-box-macos.sh"
        echo ""
        echo "  This script will:"
        echo "    1. Guide you to download the ISO from Microsoft"
        echo "       ($WIN11_DOWNLOAD_PAGE)"
        echo "    2. Create an unattended install (Autounattend.xml)"
        echo "    3. Install Windows 11 ARM64 via QEMU automatically"
        echo "    4. Configure WinRM, RDP, and vagrant user"
        echo "    5. Package and import the Vagrant box"
        echo ""
        echo "  Alternative: Import a pre-built .box file:"
        echo "    vagrant box add win11-arm /path/to/windows11-arm.box --provider qemu"
        echo ""

        if $FIX_MODE; then
            echo ""
            info "Searching for Windows 11 ARM64 ISO..."

            # Search common locations for the ISO
            FOUND_ISO=""
            for search_dir in "$HOME/Downloads" "$HOME/Desktop" "$HOME/Documents" "$HOME/.cache/detonation-chamber"; do
                if [[ -d "$search_dir" ]]; then
                    found=$(find "$search_dir" -maxdepth 2 \( \
                        -iname "*Win11*ARM*iso" -o \
                        -iname "*Windows*11*ARM*iso" -o \
                        -iname "*Win11*aarch64*iso" \
                    \) 2>/dev/null | head -1)
                    if [[ -n "$found" ]]; then
                        FOUND_ISO="$found"
                        break
                    fi
                fi
            done

            if [[ -n "$FOUND_ISO" ]]; then
                ok "Found ISO: $FOUND_ISO"
                echo ""
                info "Run the box builder to create the Vagrant box:"
                echo "    ./scripts/build-box-macos.sh --iso \"$FOUND_ISO\""
                echo ""
            else
                warn "No Windows 11 ARM64 ISO found locally."
                echo ""
                echo "  Download from: $WIN11_DOWNLOAD_PAGE"
                echo ""
                echo "  Then run:"
                echo "    ./scripts/build-box-macos.sh --iso ~/Downloads/<iso-filename>.iso"
                echo ""

                # Attempt to open the download page in the browser
                info "Opening Microsoft download page in browser..."
                open "$WIN11_DOWNLOAD_PAGE" 2>/dev/null || true
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
    echo ""
    echo "If the only missing item is the Vagrant box, build it with:"
    echo "  ./scripts/build-box-macos.sh --iso /path/to/Win11_ARM64.iso"
fi
echo ""

exit $ERRORS
