#!/bin/bash
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
# ============================================================================
# run.sh — Example: demonstrate all 4 key sourcing modes
#
# Prerequisites:
#   - elfdec-run built and in PATH or /usr/local/bin
#   - hello.elfenc created (via install.sh or manually)
#   - pub.bin + priv.bin in current directory
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

ELFDEC="${ELFDEC_BIN:-/usr/local/bin/elfdec-run}"

# Ensure we have the encrypted binary
if [ ! -f hello.elfenc ]; then
    echo "hello.elfenc not found — building it..."
    gcc -O2 hello.c -o hello
    if [ ! -f elfenc_pack ]; then
        gcc -O2 elfenc_pack.c -lsodium -o elfenc_pack
    fi
    ./elfenc_pack pub.bin hello hello.elfenc
fi

echo "============================================"
echo "  Mode 4 — File-based (ELFDEC_KEYPATH)"
echo "============================================"
echo ""
# Create a temporary key directory with only priv.bin
TMPKEYS=$(mktemp -d)
trap 'rm -rf "$TMPKEYS"' EXIT
cp priv.bin "$TMPKEYS/"

ELFDEC_KEYPATH="$TMPKEYS" "$ELFDEC" ./hello.elfenc foo bar
echo ""

echo "============================================"
echo "  Mode 2 — Keyring by ID (ELFDEC_KEYID)"
echo "============================================"
echo ""
KEYID=$(keyctl padd user "elfdec:test/hello" @s < priv.bin)
keyctl setperm "$KEYID" 0x3f030000
echo "Injected key ID: $KEYID"
ELFDEC_KEYID="$KEYID" "$ELFDEC" ./hello.elfenc
echo ""

echo "============================================"
echo "  Mode 3 — Keyring by Label (ELFDEC_LABEL)"
echo "============================================"
echo ""
echo "Searching for label: test/hello"
ELFDEC_LABEL="test/hello" "$ELFDEC" ./hello.elfenc
echo ""

# Clean up Mode 2/3 key
keyctl unlink "$KEYID" @s 2>/dev/null || true

echo "============================================"
echo "  Mode 1 — Capsule (ELFDEC_CODE)"
echo "============================================"
echo ""
# Build kcap_pack if needed
if [ ! -f kcap_pack ]; then
    gcc -O2 kcap_pack.c -lsodium -o kcap_pack
fi

CODE="demo-secret-$(date +%s)"
echo "Creating binary capsule with code: $CODE"
./kcap_pack --label test/hello --code "$CODE" --in priv.bin --out "$TMPKEYS/capsule.bin"

ELFDEC_CODE="$CODE" ELFDEC_KEYPATH="$TMPKEYS" "$ELFDEC" ./hello.elfenc
echo ""

echo "============================================"
echo "  All modes passed!"
echo "============================================"
