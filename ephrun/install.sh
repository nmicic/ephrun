#!/bin/bash
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
# ============================================================================
# install.sh — Build, install, and quick-test the ephrun toolchain
#
# What it does:
#   1. Installs build dependencies (apt)
#   2. Compiles core tools (genkey, elfenc_pack, elfdec-run)
#   3. Generates a fresh keypair
#   4. Installs elfdec-run to /usr/local/bin
#   5. Sets up ~/.elfenc/ with the private key
#   6. Runs a quick encrypt → decrypt → execute test
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Installing dependencies ==="
sudo apt-get install -y build-essential libsodium-dev libkeyutils-dev

echo ""
echo "=== Building tools ==="
gcc -O2 genkey.c -lsodium -o genkey
gcc -O2 elfenc_pack.c -lsodium -o elfenc_pack
gcc -O2 -D_GNU_SOURCE elfdec-run.c -lsodium -lkeyutils -o elfdec-run

echo ""
echo "=== Generating keypair ==="
./genkey

echo ""
echo "=== Installing elfdec-run to /usr/local/bin ==="
sudo install -o root -g root -m 0755 elfdec-run /usr/local/bin/elfdec-run

echo ""
echo "=== Setting up ~/.elfenc/ ==="
mkdir -p ~/.elfenc
cp priv.bin ~/.elfenc/priv.bin
chmod 600 ~/.elfenc/priv.bin
echo "Installed priv.bin to ~/.elfenc/ (pub.bin derived at runtime)"

echo ""
echo "=== Quick test: encrypt + decrypt + execute ==="
gcc -O2 hello.c -o hello
./elfenc_pack pub.bin hello hello.elfenc

echo "--- Mode 4 (file-based, ~/.elfenc/priv.bin) ---"
/usr/local/bin/elfdec-run ./hello.elfenc

echo ""
echo "--- Mode 2 (keyring by ID) ---"
KEYID=$(keyctl padd user "elfdec:test/hello" @s < priv.bin)
keyctl setperm "$KEYID" 0x3f030000
ELFDEC_KEYID="$KEYID" /usr/local/bin/elfdec-run ./hello.elfenc

echo ""
echo "--- Mode 3 (keyring by label) ---"
ELFDEC_LABEL="test/hello" /usr/local/bin/elfdec-run ./hello.elfenc

# Clean up test key from keyring
keyctl unlink "$KEYID" @s 2>/dev/null || true

echo ""
ls -l hello hello.elfenc
echo ""
echo "=== All done! ==="
