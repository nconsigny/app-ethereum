#!/bin/bash
# Sideload SPHINCS+ Ethereum app onto Nano S Plus
#
# Prerequisites:
#   1. pip install ledgerwallet
#   2. Connect Nano S Plus via USB
#   3. Unlock the device and open the Dashboard
#
# Usage:
#   ./sideload.sh          # Build + install
#   ./sideload.sh delete   # Uninstall the app

set -e

APP_NAME="Ethereum"
DEVICE_MODEL="nanosp"
BUILD_DIR="build/nanos2/bin"
ELF_FILE="$BUILD_DIR/app.elf"
DOCKER_IMAGE="ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest"

if [ "$1" = "delete" ]; then
    echo "Deleting app '$APP_NAME' from device..."
    ledgerctl delete "$APP_NAME"
    echo "Done."
    exit 0
fi

# Step 1: Build
echo "=== Building for Nano S Plus ==="
docker run --rm -v "$(pwd):/app" -w /app "$DOCKER_IMAGE" \
    bash -c "make clean && make CHAIN=ethereum 2>&1" | tail -5

if [ ! -f "$ELF_FILE" ]; then
    echo "ERROR: Build failed — $ELF_FILE not found"
    exit 1
fi

echo "Build OK: $(ls -lh $ELF_FILE | awk '{print $5}')"
echo ""

# Step 2: Generate manifest for sideloading
echo "=== Installing on Nano S Plus ==="
echo "Make sure your device is:"
echo "  - Connected via USB"
echo "  - Unlocked"
echo "  - On the Dashboard (home screen)"
echo ""
echo "Press Enter to continue (or Ctrl-C to cancel)..."
read -r

# Use ledgerctl to install
# The app.hex contains the loadable binary
ledgerctl install bin/app.apdu

echo ""
echo "=== Done ==="
echo "The SPHINCS+ Ethereum app should now appear on your device."
echo ""
echo "APDU commands:"
echo "  INS 0x40 — GET_SPHINCS_PUBLIC_KEY (P1=01 for confirmation)"
echo "  INS 0x42 — SPHINCS_SIGN (chunked, shows confirmation screen)"
echo ""
echo "Test with:"
echo "  # Get public key (no confirm)"
echo '  echo "e040000015058000002c8000003c800000000000000000000000" | ledgerctl send -'
echo "  # Get public key (with confirm)"
echo '  echo "e040010015058000002c8000003c800000000000000000000000" | ledgerctl send -'
