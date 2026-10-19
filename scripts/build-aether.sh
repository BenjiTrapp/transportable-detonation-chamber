#!/usr/bin/env bash
# build-aether.sh
# Cross-compiles Aether for Windows x86-64 from the host (macOS or Linux).
#
# The VM provisioner (scripts/install-aether.ps1) can build Aether itself, but
# that means installing a Zig toolchain inside the analysis VM and rebuilding
# on every fresh box. Zig cross-compiles to Windows from any host, so building
# here is faster and keeps the VM free of build tooling.
#
# Output lands in prebuilt/, which install-aether.ps1 picks up automatically
# (it is copied into the VM as C:\vagrant\prebuilt by the file provisioner).
#
# Usage:
#   ./scripts/build-aether.sh              # build into prebuilt/
#   ./scripts/build-aether.sh --clean      # rebuild from a fresh clone
#
# Requirements:
#   - Zig 0.16  (brew install zig)
#   - git

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/.build-box/aether-src"
OUT_DIR="$REPO_ROOT/prebuilt"
AETHER_REPO="https://github.com/0xsp-SRD/aether"
REQUIRED_ZIG_MAJOR_MINOR="0.16"

CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

# --- Prerequisites ---
if ! command -v zig >/dev/null 2>&1; then
    echo "[!] Zig not found. Install it with:  brew install zig" >&2
    exit 1
fi

ZIG_VERSION="$(zig version)"
case "$ZIG_VERSION" in
    "$REQUIRED_ZIG_MAJOR_MINOR"*)
        echo "[+] Zig $ZIG_VERSION" ;;
    *)
        # Aether's build.zig uses the 0.16 b.createModule API; other majors fail.
        echo "[!] Zig $ZIG_VERSION found, but Aether needs $REQUIRED_ZIG_MAJOR_MINOR.x" >&2
        exit 1 ;;
esac

# --- Source ---
if [ "$CLEAN" = "1" ] && [ -d "$SRC_DIR" ]; then
    echo "[*] Removing previous source tree"
    rm -rf "$SRC_DIR"
fi

if [ -d "$SRC_DIR/.git" ]; then
    echo "[*] Updating Aether source"
    git -C "$SRC_DIR" fetch --depth 1 origin main --quiet
    git -C "$SRC_DIR" reset --hard origin/main --quiet
else
    echo "[*] Cloning Aether source"
    mkdir -p "$(dirname "$SRC_DIR")"
    git clone --depth 1 "$AETHER_REPO" "$SRC_DIR" --quiet
fi

COMMIT="$(git -C "$SRC_DIR" rev-parse --short HEAD)"

# --- Build ---
# build.zig already defaults to x86_64-windows, so no -Dtarget is needed.
echo "[*] Building Aether (ReleaseSafe, x86_64-windows)"
(cd "$SRC_DIR" && zig build -Doptimize=ReleaseSafe)

BUILT="$SRC_DIR/zig-out/bin/Aether.exe"
if [ ! -f "$BUILT" ]; then
    echo "[!] Build produced no Aether.exe" >&2
    exit 1
fi

# --- Stage for the VM ---
mkdir -p "$OUT_DIR"
cp "$BUILT" "$OUT_DIR/Aether.exe"
rm -rf "$OUT_DIR/rules"
cp -R "$SRC_DIR/rules" "$OUT_DIR/rules"

SIZE_KB=$(( $(wc -c < "$OUT_DIR/Aether.exe") / 1024 ))
RULE_COUNT=$(find "$OUT_DIR/rules" -name '*.json' | wc -l | tr -d ' ')

echo
echo "[+] Aether built from commit $COMMIT"
echo "    Binary: $OUT_DIR/Aether.exe (${SIZE_KB} KB)"
echo "    Rules:  $OUT_DIR/rules ($RULE_COUNT files)"
echo
echo "    'make up' copies prebuilt/ into the VM and install-aether.ps1 uses it."
echo "    For a running VM:  python3 scripts/deploy-utm.py --aether"
