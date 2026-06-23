#!/bin/bash
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
# ============================================================================
# test.sh — End-to-end test suite for ephrun
#
# Runs all core tools through each key sourcing mode and verifies success.
# Must be run on Linux with libsodium-dev, libkeyutils-dev installed.
#
# Usage:  bash test.sh
# ============================================================================

set -euo pipefail

PASS=0
FAIL=0
TESTS=()

# ---------- helpers ----------

red()   { printf '\033[1;31m%s\033[0m' "$*"; }
green() { printf '\033[1;32m%s\033[0m' "$*"; }
bold()  { printf '\033[1m%s\033[0m' "$*"; }

pass() {
    PASS=$((PASS+1))
    TESTS+=("PASS: $1")
    echo "  $(green '✓') $1"
}

fail() {
    FAIL=$((FAIL+1))
    TESTS+=("FAIL: $1 — $2")
    echo "  $(red '✗') $1"
    echo "    → $2"
}

banner() {
    echo ""
    bold "━━━ $1 ━━━"
    echo ""
}

# ---------- setup ----------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d /tmp/ephrun_test.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

SRC="$SCRIPT_DIR/ephrun"
KEYPUSH_SRC="$SCRIPT_DIR/keypush"

cd "$SRC"

banner "Build phase"

# ── Build: genkey ──
if gcc -O2 -Wall -Wextra genkey.c -lsodium -o "$WORK/genkey" 2>"$WORK/build_genkey.log"; then
    pass "Build genkey"
else
    fail "Build genkey" "$(cat "$WORK/build_genkey.log")"
fi

# ── Build: elfenc_pack ──
if gcc -O2 -Wall -Wextra elfenc_pack.c -lsodium -o "$WORK/elfenc_pack" 2>"$WORK/build_elfenc_pack.log"; then
    pass "Build elfenc_pack"
else
    fail "Build elfenc_pack" "$(cat "$WORK/build_elfenc_pack.log")"
fi

# ── Build: elfdec-run ──
if gcc -O2 -Wall -Wextra -D_GNU_SOURCE elfdec-run.c -lsodium -lkeyutils -o "$WORK/elfdec-run" 2>"$WORK/build_elfdec.log"; then
    pass "Build elfdec-run"
else
    fail "Build elfdec-run" "$(cat "$WORK/build_elfdec.log")"
fi

# ── Build: kcap_pack ──
if gcc -O2 -Wall -Wextra kcap_pack.c -lsodium -o "$WORK/kcap_pack" 2>"$WORK/build_kcap.log"; then
    pass "Build kcap_pack"
else
    fail "Build kcap_pack" "$(cat "$WORK/build_kcap.log")"
fi

# ── Build: test hello binary ──
if gcc -O2 hello.c -o "$WORK/hello" 2>"$WORK/build_hello.log"; then
    pass "Build hello test binary"
else
    fail "Build hello test binary" "$(cat "$WORK/build_hello.log")"
fi

# ── Build: keypush_send ──
if gcc -O2 -Wall -Wextra "$KEYPUSH_SRC/keypush_send.c" -lsodium -o "$WORK/keypush_send" 2>"$WORK/build_ksend.log"; then
    pass "Build keypush_send"
else
    fail "Build keypush_send" "$(cat "$WORK/build_ksend.log")"
fi

# ── Build: keypushd ──
if gcc -O2 -Wall -Wextra "$KEYPUSH_SRC/keypushd.c" -lsodium -lkeyutils -o "$WORK/keypushd" 2>"$WORK/build_kd.log"; then
    pass "Build keypushd"
else
    fail "Build keypushd" "$(cat "$WORK/build_kd.log")"
fi

banner "Key generation"

cd "$WORK"

# ── genkey ──
GENKEY_OUT=$("$WORK/genkey" 2>&1) || true
if [ -f "$WORK/pub.bin" ] && [ -f "$WORK/priv.bin" ]; then
    PUB_SIZE=$(stat -c%s "$WORK/pub.bin" 2>/dev/null || stat -f%z "$WORK/pub.bin")
    PRIV_SIZE=$(stat -c%s "$WORK/priv.bin" 2>/dev/null || stat -f%z "$WORK/priv.bin")
    if [ "$PUB_SIZE" -eq 32 ] && [ "$PRIV_SIZE" -eq 32 ]; then
        pass "genkey creates 32-byte pub.bin + priv.bin"
    else
        fail "genkey key sizes" "pub=$PUB_SIZE priv=$PRIV_SIZE (expected 32)"
    fi
else
    fail "genkey output files" "pub.bin or priv.bin missing"
fi

# ── genkey should NOT print private key ──
if echo "$GENKEY_OUT" | grep -qi "priv.*hex"; then
    fail "genkey does not leak priv key" "private key hex found in stdout"
else
    pass "genkey does not leak priv key to stdout"
fi

banner "Encryption"

# ── elfenc_pack ──
if "$WORK/elfenc_pack" "$WORK/pub.bin" "$WORK/hello" "$WORK/hello.elfenc" 2>"$WORK/enc.log"; then
    if [ -f "$WORK/hello.elfenc" ]; then
        # Check ELFENC1 magic
        MAGIC=$(head -c7 "$WORK/hello.elfenc")
        if [ "$MAGIC" = "ELFENC1" ]; then
            pass "elfenc_pack produces valid ELFENC1 file"
        else
            fail "elfenc_pack magic" "expected ELFENC1, got: $MAGIC"
        fi
    else
        fail "elfenc_pack output" "hello.elfenc not created"
    fi
else
    fail "elfenc_pack" "$(cat "$WORK/enc.log")"
fi

banner "Mode 4 — File-based decryption (ELFDEC_KEYPATH)"

# ── Decrypt with ELFDEC_KEYPATH (only priv.bin needed) ──
mkdir -p "$WORK/keys"
cp "$WORK/priv.bin" "$WORK/keys/"

DEC_OUT=$(ELFDEC_KEYPATH="$WORK/keys" "$WORK/elfdec-run" "$WORK/hello.elfenc" testarg1 testarg2 2>"$WORK/dec4.log") || true
if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
    pass "Mode 4: ELFDEC_KEYPATH decrypt + execute"
else
    fail "Mode 4: ELFDEC_KEYPATH decrypt" "output: $DEC_OUT | stderr: $(cat "$WORK/dec4.log")"
fi

# Verify argv passthrough
if echo "$DEC_OUT" | grep -q "argv\[1\]=testarg1" && echo "$DEC_OUT" | grep -q "argv\[2\]=testarg2"; then
    pass "Mode 4: argv passthrough works"
else
    fail "Mode 4: argv passthrough" "output: $DEC_OUT"
fi

# ── Verify pub.bin is NOT required in file mode ──
if [ ! -f "$WORK/keys/pub.bin" ]; then
    pass "Mode 4: pub.bin not required (derived from priv.bin)"
else
    fail "Mode 4: pub.bin presence" "pub.bin should not be in keys dir"
fi

banner "Mode 2 — Keyring by ID (ELFDEC_KEYID)"

# ── Inject key into session keyring ──
KEYID=$(keyctl padd user "elfdec:test/hello" @s < "$WORK/priv.bin" 2>"$WORK/keyring.log") || true
if [ -n "$KEYID" ] && [ "$KEYID" -gt 0 ] 2>/dev/null; then
    pass "Keyring: inject key (ID=$KEYID)"
    keyctl setperm "$KEYID" 0x3f030000 2>/dev/null || true

    # ── Decrypt with ELFDEC_KEYID ──
    DEC_OUT=$(ELFDEC_KEYID="$KEYID" "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec2.log") || true
    if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
        pass "Mode 2: ELFDEC_KEYID decrypt + execute"
    else
        fail "Mode 2: ELFDEC_KEYID decrypt" "output: $DEC_OUT | stderr: $(cat "$WORK/dec2.log")"
    fi
else
    fail "Keyring: inject key" "keyctl padd failed: $(cat "$WORK/keyring.log")"
fi

banner "Mode 3 — Keyring by Label (ELFDEC_LABEL)"

# Key "elfdec:test/hello" was already injected above
DEC_OUT=$(ELFDEC_LABEL="test/hello" "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec3.log") || true
if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
    pass "Mode 3: ELFDEC_LABEL decrypt + execute"
else
    fail "Mode 3: ELFDEC_LABEL decrypt" "output: $DEC_OUT | stderr: $(cat "$WORK/dec3.log")"
fi

# Clean up keyring key
keyctl unlink "$KEYID" @s 2>/dev/null || true

banner "Mode 1 — Capsule (ELFDEC_CODE) — binary format"

# ── Create binary capsule ──
CAPSULE_CODE="test-code-$(date +%s)"
if "$WORK/kcap_pack" --label test/hello --code "$CAPSULE_CODE" --in "$WORK/priv.bin" --out "$WORK/capsule.bin" 2>"$WORK/kcap.log"; then
    if [ -f "$WORK/capsule.bin" ]; then
        CAP_FAMILY=$(head -c4 "$WORK/capsule.bin")
        CAP_VERSION=$(head -c5 "$WORK/capsule.bin" | tail -c1 | od -An -tu1 | tr -d ' ')
        CAP_PROJECT=$(head -c6 "$WORK/capsule.bin" | tail -c1 | od -An -tu1 | tr -d ' ')
        if [ "$CAP_FAMILY" = "KCAP" ] && [ "$CAP_VERSION" = "1" ] && [ "$CAP_PROJECT" = "1" ]; then
            pass "kcap_pack creates valid KCAP3 binary capsule (family=KCAP version=1 project=1)"
        else
            fail "kcap_pack binary magic" "expected KCAP/0x01/0x01 (got family=$CAP_FAMILY version=$CAP_VERSION project=$CAP_PROJECT)"
        fi
    else
        fail "kcap_pack binary output" "capsule.bin not created"
    fi
else
    fail "kcap_pack binary" "$(cat "$WORK/kcap.log")"
fi

# ── Decrypt with capsule.bin via ELFDEC_KEYPATH ──
mkdir -p "$WORK/capkeys"
cp "$WORK/capsule.bin" "$WORK/capkeys/"

DEC_OUT=$(ELFDEC_CODE="$CAPSULE_CODE" ELFDEC_KEYPATH="$WORK/capkeys" "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec1b.log") || true
if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
    pass "Mode 1: binary capsule decrypt + execute"
else
    fail "Mode 1: binary capsule decrypt" "output: $DEC_OUT | stderr: $(cat "$WORK/dec1b.log")"
fi

banner "Mode 1 — Capsule (ELFDEC_CODE) — JSON output deprecated (KCAP3)"

# ── kcap_pack --json must now refuse, per KCAP3 / D-6 deprecation ──
if "$WORK/kcap_pack" --label test/hello --code "$CAPSULE_CODE" --in "$WORK/priv.bin" --out "$WORK/capsule.json" --json 2>"$WORK/kcap_json.log"; then
    fail "kcap_pack --json rejected" "kcap_pack accepted --json (KCAP3 should refuse)"
else
    if grep -q -i "json.*deprecated\|deprecated.*json" "$WORK/kcap_json.log"; then
        pass "kcap_pack --json correctly rejected with deprecation message"
    else
        fail "kcap_pack --json error message" "exited non-zero but expected message; got: $(cat "$WORK/kcap_json.log")"
    fi
fi

banner "Mode 1 — Capsule with TTL"

# ── Create capsule with long TTL (should work) ──
if "$WORK/kcap_pack" --label test/ttl --code "$CAPSULE_CODE" --ttl 3600 --in "$WORK/priv.bin" --out "$WORK/capsule_ttl.bin" 2>/dev/null; then
    mkdir -p "$WORK/capkeys_ttl"
    cp "$WORK/capsule_ttl.bin" "$WORK/capkeys_ttl/capsule.bin"

    DEC_OUT=$(ELFDEC_CODE="$CAPSULE_CODE" ELFDEC_KEYPATH="$WORK/capkeys_ttl" "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec_ttl.log") || true
    if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
        pass "Mode 1: capsule with TTL=3600 works"
    else
        fail "Mode 1: capsule with TTL=3600" "output: $DEC_OUT | stderr: $(cat "$WORK/dec_ttl.log")"
    fi
else
    fail "kcap_pack with TTL" "build failed"
fi

banner "Negative tests"

# ── Wrong code should fail ──
DEC_OUT=$(ELFDEC_CODE="wrong-code" ELFDEC_KEYPATH="$WORK/capkeys" "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec_wrong.log") || true
if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
    fail "Negative: wrong code rejected" "decryption succeeded with wrong code!"
else
    pass "Negative: wrong capsule code correctly rejected"
fi

# ── Corrupt elfenc should fail ──
echo "NOT_AN_ELFENC_FILE_GARBAGE" > "$WORK/garbage.elfenc"
DEC_OUT=$(ELFDEC_KEYPATH="$WORK/keys" "$WORK/elfdec-run" "$WORK/garbage.elfenc" 2>"$WORK/dec_garb.log") || true
if echo "$DEC_OUT" | grep -q "hello"; then
    fail "Negative: corrupt elfenc rejected" "decryption succeeded on garbage!"
else
    pass "Negative: corrupt .elfenc correctly rejected"
fi

# ── Missing key should fail ──
mkdir -p "$WORK/empty_keys"
DEC_OUT=$(ELFDEC_KEYPATH="$WORK/empty_keys" HOME="/nonexistent" "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec_nokey.log") || true
if echo "$DEC_OUT" | grep -q "hello"; then
    fail "Negative: missing key rejected" "decryption succeeded without key!"
else
    pass "Negative: missing key correctly rejected"
fi

# ── Wrong keypair should fail ──
# Generate a second keypair and try to decrypt with it
cd "$WORK"
mkdir -p "$WORK/wrongkeys"
(cd "$WORK/wrongkeys" && "$WORK/genkey" >/dev/null 2>&1)
DEC_OUT=$(ELFDEC_KEYPATH="$WORK/wrongkeys" "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec_wrongkey.log") || true
if echo "$DEC_OUT" | grep -q "hello"; then
    fail "Negative: wrong keypair rejected" "decryption succeeded with wrong key!"
else
    pass "Negative: wrong keypair correctly rejected"
fi

banner "Mode 1 — Capsule in keyring"

# ── Store capsule in keyring, decrypt via ELFDEC_LABEL ──
CAP_KEYID=$(keyctl padd user "elfdec_caps:test/capring" @s < "$WORK/capsule.bin" 2>"$WORK/cap_keyring.log") || true
if [ -n "$CAP_KEYID" ] && [ "$CAP_KEYID" -gt 0 ] 2>/dev/null; then
    pass "Capsule: inject into keyring (ID=$CAP_KEYID)"

    DEC_OUT=$(ELFDEC_CODE="$CAPSULE_CODE" ELFDEC_LABEL="test/capring" "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec_capring.log") || true
    if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
        pass "Mode 1: capsule from keyring decrypt + execute"
    else
        fail "Mode 1: capsule from keyring" "output: $DEC_OUT | stderr: $(cat "$WORK/dec_capring.log")"
    fi

    keyctl unlink "$CAP_KEYID" @s 2>/dev/null || true
else
    fail "Capsule: inject into keyring" "keyctl padd failed: $(cat "$WORK/cap_keyring.log")"
fi

# ============================================================================
# §B code-hygiene tests — D-16 /dev/shm hardening + D-17 env scrubbing
# Refs: ACCEPTANCE_CRITERIA.md AC-03-04, AC-03-05, AC-03-07
# ============================================================================

banner "AC-03-07 — Env-var scrubbing before exec (D-17)"

# Build env_dump workload (prints /proc/self/environ)
if gcc -O2 -Wall -Wextra "$SRC/env_dump.c" -o "$WORK/env_dump" 2>"$WORK/build_envdump.log"; then
    pass "Build env_dump test workload"
else
    fail "Build env_dump test workload" "$(cat "$WORK/build_envdump.log")"
fi

# Encrypt env_dump
if "$WORK/elfenc_pack" "$WORK/pub.bin" "$WORK/env_dump" "$WORK/env_dump.elfenc" 2>"$WORK/enc_envdump.log"; then
    pass "Encrypt env_dump"
else
    fail "Encrypt env_dump" "$(cat "$WORK/enc_envdump.log")"
fi

# ── AC-03-07 (memfd path): workload's /proc/self/environ has no ELFDEC_* ──
ENV_OUT=$(ELFDEC_CODE="$CAPSULE_CODE" \
          ELFDEC_KEYPATH="$WORK/capkeys" \
          ELFDEC_LABEL="test/hello" \
          "$WORK/elfdec-run" "$WORK/env_dump.elfenc" 2>"$WORK/envdump_memfd.log") || true

if echo "$ENV_OUT" | grep -qE '^(ELFDEC_CODE|ELFDEC_KEYID|ELFDEC_LABEL|ELFDEC_KEYPATH|ELFDEC_CAP)='; then
    LEAKS=$(echo "$ENV_OUT" | grep -E '^(ELFDEC_CODE|ELFDEC_KEYID|ELFDEC_LABEL|ELFDEC_KEYPATH|ELFDEC_CAP)=' | tr '\n' ',')
    fail "AC-03-07: memfd path scrubs ELFDEC_*" "leaked: $LEAKS"
else
    pass "AC-03-07: memfd path scrubs ELFDEC_CODE/KEYID/LABEL/KEYPATH/CAP"
fi

# Sanity: a non-scrubbed unrelated var (PATH) should still pass through
if echo "$ENV_OUT" | grep -q '^PATH='; then
    pass "AC-03-07: non-ephrun env vars pass through (PATH preserved)"
else
    fail "AC-03-07: PATH passed through" "PATH= not in workload env (over-scrubbing?)"
fi

# Build LD_PRELOAD shim for forcing fexecve errno (drives AC-03-04 / AC-03-05)
if gcc -fPIC -shared -O2 "$SRC/test_fexecve_shim.c" -ldl -o "$WORK/libtest_fexecve_shim.so" 2>"$WORK/build_shim.log"; then
    pass "Build fexecve LD_PRELOAD shim"
else
    fail "Build fexecve LD_PRELOAD shim" "$(cat "$WORK/build_shim.log")"
fi

# Linux ETXTBSY = 26 ; ENOEXEC = 8
ETXTBSY=26
ENOEXEC=8

banner "AC-03-05 — /dev/shm fallback hardening (D-16)"

# Helper: force any leftover /dev/shm/elfdec-* gone before each test
rm -f /dev/shm/elfdec-* 2>/dev/null || true

# ── AC-03-05(a): non-ETXTBSY fexecve fail → fatal exit, NO /dev/shm file ──
RC_A=0
LD_PRELOAD="$WORK/libtest_fexecve_shim.so" \
ELFDEC_TEST_FEXECVE_ERRNO="$ENOEXEC" \
ELFDEC_KEYPATH="$WORK/keys" \
"$WORK/elfdec-run" "$WORK/hello.elfenc" >"$WORK/dec_a05a.out" 2>"$WORK/dec_a05a.log" || RC_A=$?

LEFTOVER=$(find /dev/shm -maxdepth 1 -name 'elfdec-*' -printf '%p ' 2>/dev/null)
if [ "$RC_A" -ne 0 ] && [ -z "$LEFTOVER" ]; then
    pass "AC-03-05(a): non-ETXTBSY fexecve → fatal, no /dev/shm file"
else
    fail "AC-03-05(a): non-ETXTBSY fexecve" "rc=$RC_A leftover='$LEFTOVER' stderr=$(cat "$WORK/dec_a05a.log")"
    # Cleanup if test left files
    rm -f /dev/shm/elfdec-* 2>/dev/null || true
fi

# ── AC-03-05(b)+(c): ETXTBSY fallback → workload runs, /dev/shm clean after ──
DEC_OUT=$(LD_PRELOAD="$WORK/libtest_fexecve_shim.so" \
          ELFDEC_TEST_FEXECVE_ERRNO="$ETXTBSY" \
          ELFDEC_KEYPATH="$WORK/keys" \
          "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec_a05bc.log") || true

LEFTOVER=$(find /dev/shm -maxdepth 1 -name 'elfdec-*' -printf '%p ' 2>/dev/null)

if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
    pass "AC-03-05(b): ETXTBSY fallback → workload runs (execveat AT_EMPTY_PATH path)"
else
    fail "AC-03-05(b): ETXTBSY fallback workload run" "out=$DEC_OUT stderr=$(cat "$WORK/dec_a05bc.log")"
fi

if [ -z "$LEFTOVER" ]; then
    pass "AC-03-05(c): /dev/shm clean after successful fallback exec"
else
    fail "AC-03-05(c): /dev/shm clean" "leftover files: $LEFTOVER"
    rm -f /dev/shm/elfdec-* 2>/dev/null || true
fi

# ── AC-03-04(b modern): ETXTBSY fallback + bad ELF → execveat fails →
#    /dev/shm file is wiped (via /proc/self/fd/N) and unlinked ──
# Use a non-ELF payload to make execveat ENOEXEC after fallback runs.
echo "this is not an ELF binary, just plain text for testing" > "$WORK/notelf"
"$WORK/elfenc_pack" "$WORK/pub.bin" "$WORK/notelf" "$WORK/notelf.elfenc" 2>/dev/null

RC_B=0
LD_PRELOAD="$WORK/libtest_fexecve_shim.so" \
ELFDEC_TEST_FEXECVE_ERRNO="$ETXTBSY" \
ELFDEC_KEYPATH="$WORK/keys" \
"$WORK/elfdec-run" "$WORK/notelf.elfenc" >"$WORK/dec_a04b.out" 2>"$WORK/dec_a04b.log" || RC_B=$?

LEFTOVER=$(find /dev/shm -maxdepth 1 -name 'elfdec-*' -printf '%p ' 2>/dev/null)
if [ "$RC_B" -ne 0 ] && [ -z "$LEFTOVER" ]; then
    pass "AC-03-04(b modern): ETXTBSY fallback + exec failure → /dev/shm clean"
else
    fail "AC-03-04(b modern): /dev/shm clean on exec fail" "rc=$RC_B leftover='$LEFTOVER' stderr=$(cat "$WORK/dec_a04b.log")"
    rm -f /dev/shm/elfdec-* 2>/dev/null || true
fi

banner "AC-03-07 — Env-var scrubbing on /dev/shm fallback path"

# ── AC-03-07 (fallback path): same scrub guarantee via ETXTBSY route ──
ENV_OUT=$(LD_PRELOAD="$WORK/libtest_fexecve_shim.so" \
          ELFDEC_TEST_FEXECVE_ERRNO="$ETXTBSY" \
          ELFDEC_CODE="$CAPSULE_CODE" \
          ELFDEC_KEYPATH="$WORK/capkeys" \
          ELFDEC_LABEL="test/hello" \
          "$WORK/elfdec-run" "$WORK/env_dump.elfenc" 2>"$WORK/envdump_fallback.log") || true

LEFTOVER=$(find /dev/shm -maxdepth 1 -name 'elfdec-*' -printf '%p ' 2>/dev/null)
rm -f /dev/shm/elfdec-* 2>/dev/null || true

if echo "$ENV_OUT" | grep -qE '^(ELFDEC_CODE|ELFDEC_KEYID|ELFDEC_LABEL|ELFDEC_KEYPATH|ELFDEC_CAP)='; then
    LEAKS=$(echo "$ENV_OUT" | grep -E '^(ELFDEC_CODE|ELFDEC_KEYID|ELFDEC_LABEL|ELFDEC_KEYPATH|ELFDEC_CAP)=' | tr '\n' ',')
    fail "AC-03-07: fallback path scrubs ELFDEC_*" "leaked: $LEAKS"
else
    pass "AC-03-07: fallback path (ETXTBSY route) scrubs ELFDEC_CODE/KEYID/LABEL/KEYPATH/CAP"
fi

if [ -z "$LEFTOVER" ]; then
    pass "AC-03-07 fallback path: /dev/shm clean after env_dump exec"
else
    fail "AC-03-07 fallback /dev/shm clean" "leftover: $LEFTOVER"
fi

banner "AC-03-08 — LD_PRELOAD stripped from workload envp (D-19)"

# Pick a real .so the dynamic linker would actually honor — using a bogus path
# would test argument handling, not loader-scrub behavior. Cover both x86_64
# and aarch64 multiarch directories (SPEC.md supports both).
LDP_TARGET=""
for cand in \
    /lib/x86_64-linux-gnu/libnss_files.so.2 \
    /lib/x86_64-linux-gnu/libdl.so.2 \
    /lib/aarch64-linux-gnu/libnss_files.so.2 \
    /lib/aarch64-linux-gnu/libdl.so.2 \
    /lib64/libdl.so.2 \
    /usr/lib/libdl.so.2 ; do
    if [ -f "$cand" ]; then LDP_TARGET="$cand"; break; fi
done
# Last-resort discovery: ask the dynamic loader directly. Picks the first .so
# ldconfig knows about, which exists on every glibc-based distro regardless
# of multiarch layout.
if [ -z "$LDP_TARGET" ] && command -v ldconfig >/dev/null 2>&1; then
    LDP_TARGET=$(ldconfig -p 2>/dev/null \
        | awk -F'=> ' '/libdl\.so\.2 |libnss_files\.so\.2 / {print $2; exit}' \
        | tr -d ' ')
    [ -n "$LDP_TARGET" ] && [ ! -f "$LDP_TARGET" ] && LDP_TARGET=""
fi

if [ -z "$LDP_TARGET" ]; then
    fail "AC-03-08: LD_PRELOAD target available" "no usable .so found via /lib/{x86_64,aarch64}-linux-gnu, /lib64, /usr/lib, or ldconfig -p"
else
    RC_D19=0
    ENV_OUT=$(LD_PRELOAD="$LDP_TARGET" \
              NODE_OPTIONS="--require=/tmp/x.js" \
              BASH_ENV="/tmp/y.sh" \
              ELFDEC_KEYPATH="$WORK/keys" \
              "$WORK/elfdec-run" "$WORK/env_dump.elfenc" 2>"$WORK/envdump_d19.log") || RC_D19=$?

    # Note: the negative grep below would pass vacuously if elfdec-run
    # failed before env_dump executed. Require rc==0 AND a positive sentinel
    # (PATH= is inherited from the test shell, so env_dump should always emit
    # at least that line if it ran at all).
    if [ "$RC_D19" -ne 0 ] || ! echo "$ENV_OUT" | grep -q '^PATH='; then
        fail "AC-03-08: env_dump did not execute" \
             "rc=$RC_D19 stderr=$(cat "$WORK/envdump_d19.log") env_out_first=$(echo "$ENV_OUT" | head -1)"
    elif echo "$ENV_OUT" | grep -qE '^(LD_PRELOAD|NODE_OPTIONS|BASH_ENV)='; then
        LEAKS=$(echo "$ENV_OUT" | grep -E '^(LD_PRELOAD|NODE_OPTIONS|BASH_ENV)=' | tr '\n' ',')
        fail "AC-03-08: D-19 loader-scrub vars leaked to workload" "leaked: $LEAKS"
    else
        pass "AC-03-08: workload envp clean of LD_PRELOAD/NODE_OPTIONS/BASH_ENV (preload target: $LDP_TARGET)"
    fi
fi

banner "D-18 — TracerPid defense (defense-in-depth)"

# Tests rely on strace; skip section if it's not installed
if ! command -v strace >/dev/null 2>&1; then
    fail "D-18: strace required" "strace not installed"
else
    # ── (1) Baseline no-tracer: ensure normal path still works ──
    DEC_OUT=$(ELFDEC_KEYPATH="$WORK/keys" "$WORK/elfdec-run" "$WORK/hello.elfenc" 2>"$WORK/dec_d18_baseline.log") || true
    if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
        pass "D-18 (1): baseline no-tracer run succeeds"
    else
        fail "D-18 (1): baseline no-tracer" "out=$DEC_OUT stderr=$(cat "$WORK/dec_d18_baseline.log")"
    fi

    # ── (2) Negative: under strace, elfdec-run aborts before any decryption work ──
    RC_T=0
    strace -f -o "$WORK/strace_neg.log" \
        env ELFDEC_KEYPATH="$WORK/keys" \
            "$WORK/elfdec-run" "$WORK/hello.elfenc" \
        >"$WORK/dec_d18_neg.out" 2>"$WORK/dec_d18_neg.err" || RC_T=$?

    if [ "$RC_T" -ne 0 ] && grep -q "refusing to run under tracer" "$WORK/dec_d18_neg.err"; then
        pass "D-18 (2): strace-attached run rejected with TracerPid message"
    else
        fail "D-18 (2): strace-attached rejection" "rc=$RC_T stderr=$(cat "$WORK/dec_d18_neg.err")"
    fi

    # The check fires BEFORE decryption — verify the abort really did happen
    # before any sensitive syscall by greping the strace log itself (where
    # syscalls are observable) rather than the app's stderr (where they aren't).
    # If the tracer-check ordering is correct, strace must NOT see memfd_create
    # or execveat. open()/read() on /proc/self/status is expected.
    if ! grep -qE "memfd_create|execveat" "$WORK/strace_neg.log"; then
        pass "D-18 (2b): no memfd_create/execveat observed by strace before abort"
    else
        fail "D-18 (2b): rejection ordering" \
             "strace observed sensitive syscalls: $(grep -E "memfd_create|execveat" "$WORK/strace_neg.log" | head -3)"
    fi

    # ── (3) Bypass: ELFDEC_ALLOW_TRACE=1 lets it run under strace ──
    DEC_OUT=$(strace -f -o "$WORK/strace_bypass.log" \
              env ELFDEC_ALLOW_TRACE=1 ELFDEC_KEYPATH="$WORK/keys" \
                  "$WORK/elfdec-run" "$WORK/hello.elfenc" \
              2>"$WORK/dec_d18_bypass.err") || true

    if echo "$DEC_OUT" | grep -q "hello from encrypted ELF!"; then
        pass "D-18 (3): ELFDEC_ALLOW_TRACE=1 bypass works under strace"
    else
        fail "D-18 (3): bypass" "out=$DEC_OUT stderr=$(cat "$WORK/dec_d18_bypass.err")"
    fi

    # ── (4) Env scrub: ELFDEC_ALLOW_TRACE NOT inherited by the workload ──
    ENV_OUT=$(ELFDEC_ALLOW_TRACE=1 ELFDEC_KEYPATH="$WORK/keys" \
              "$WORK/elfdec-run" "$WORK/env_dump.elfenc" \
              2>"$WORK/dec_d18_envscrub.err") || true

    if echo "$ENV_OUT" | grep -q '^ELFDEC_ALLOW_TRACE='; then
        fail "D-18 (4): ELFDEC_ALLOW_TRACE scrubbed" "leaked: $(echo "$ENV_OUT" | grep '^ELFDEC_ALLOW_TRACE=')"
    else
        pass "D-18 (4): ELFDEC_ALLOW_TRACE scrubbed from workload env"
    fi
fi

banner "AC-03-09 — Argon2id under cgroup memory pressure (Mode A clean-OOM)"

# AC-03-09 / SECURITY.md §3.2: elfdec-run must NOT die via SIGKILL when the
# cgroup memory ceiling forces Argon2id allocation to fail. It must surface
# a clean ENOMEM-flavored error.
#
# Two cases are required (single-case test passes
# vacuously on hosts with enough headroom):
#
#   (a) Positive — MemoryMax=96M (32 MiB headroom over Argon2id 64 MiB):
#       must succeed cleanly. Validates the normal path inside a constrained
#       cgroup.
#   (c) Negative — MemoryMax=24M (well below the 64 MiB Argon2id needs):
#       must fail with rc != 0 AND not SIGKILL AND ENOMEM-flavored stderr.
#       This is the case that proves the OOM path doesn't go silent or
#       map ENOMEM to a misleading "Permission denied".
#
# Implementation: systemd-run --user --scope is a hard dependency. If it is
# absent (rare — every systemd distro since 2015 has it) or user cgroup
# delegation is off (Docker without --cap-add SYS_ADMIN, some CI runners),
# the case fails with an informative message. Adding a real "skip" accounting
# would be inconsistent with how strace-absence is handled in D-18 above.
#
# Reuses Mode-1 capsule keypath ($WORK/capkeys + $CAPSULE_CODE) — capsule
# sourcing is what triggers the Argon2id 64 MiB allocation.

if ! command -v systemd-run >/dev/null 2>&1; then
    fail "AC-03-09: systemd-run unavailable" "install systemd or run on a host with user-scope delegation (Docker without --cap-add SYS_ADMIN may not have it)"
elif ! systemd-run --user --scope --quiet -p MemoryMax=96M -- /bin/true 2>/dev/null; then
    fail "AC-03-09: systemd-run --user --scope -p MemoryMax= unsupported" \
         "user cgroup delegation likely off; check 'cat /sys/fs/cgroup/user.slice/user-\$UID.slice/cgroup.controllers'"
else
    # ── (a) Positive case: MemoryMax=96M, must succeed ──
    RC_CG=0
    OUT_CG=$(systemd-run --user --scope --quiet -p MemoryMax=96M -- \
                env ELFDEC_CODE="$CAPSULE_CODE" ELFDEC_KEYPATH="$WORK/capkeys" \
                    "$WORK/elfdec-run" "$WORK/hello.elfenc" \
                2>"$WORK/cg_pos.err") || RC_CG=$?

    if [ "$RC_CG" -eq 137 ] || grep -qiE "killed|signal 9|SIGKILL" "$WORK/cg_pos.err"; then
        fail "AC-03-09 (a): SIGKILL under MemoryMax=96M (32 MiB headroom should be enough)" \
             "rc=$RC_CG stderr=$(head -c 400 "$WORK/cg_pos.err")"
    elif [ "$RC_CG" -eq 0 ] && echo "$OUT_CG" | grep -q "hello from encrypted ELF!"; then
        pass "AC-03-09 (a): clean exec succeed under MemoryMax=96M"
    else
        fail "AC-03-09 (a): unexpected failure under MemoryMax=96M" \
             "rc=$RC_CG out=$OUT_CG stderr=$(head -c 400 "$WORK/cg_pos.err")"
    fi

    # ── (c) Negative case: MemoryMax=24M, must fail cleanly with ENOMEM ──
    # 24 MiB is well below Argon2id's 64 MiB allocation. The Argon2id mmap
    # request alone exceeds the cgroup ceiling and the kernel rejects it
    # before pages are committed, so malloc returns NULL. crypto_pwhash
    # returns -1, kcap3_unpack sets errno=ENOMEM, elfdec-run's xdie prints
    # "capsule decrypt failed (Cannot allocate memory)". Must not be SIGKILL.
    RC_NEG=0
    OUT_NEG=$(systemd-run --user --scope --quiet -p MemoryMax=24M -- \
                env ELFDEC_CODE="$CAPSULE_CODE" ELFDEC_KEYPATH="$WORK/capkeys" \
                    "$WORK/elfdec-run" "$WORK/hello.elfenc" \
                2>"$WORK/cg_neg.err") || RC_NEG=$?

    # Kernel-version conditional per D-20 — on kernel < 6.x,
    # the cgroup OOM-killer fires before libsodium's crypto_pwhash can
    # return ENOMEM to userspace, so SIGKILL is the expected outcome and
    # not an ephrun bug. Closing this would require RLIMIT_AS/RLIMIT_DATA
    # to provoke userspace ENOMEM ahead of Argon2id — out of scope per D-20.
    KMAJOR=$(uname -r 2>/dev/null | cut -d. -f1)
    if [ "$RC_NEG" -eq 137 ] || grep -qiE "killed|signal 9|SIGKILL" "$WORK/cg_neg.err"; then
        if [ -n "$KMAJOR" ] && [ "$KMAJOR" -lt 6 ] 2>/dev/null; then
            pass "AC-03-09 (c): SIGKILL on kernel $(uname -r) is the documented behavior (D-20 — cgroup OOM-killer fires before crypto_pwhash returns)"
        else
            fail "AC-03-09 (c): SIGKILL on kernel $(uname -r) (≥ 6.x — must surface ENOMEM cleanly, not OOM-kill; check D-20 if this is a 5.x baseline)" \
                 "rc=$RC_NEG stderr=$(head -c 400 "$WORK/cg_neg.err")"
        fi
    elif [ "$RC_NEG" -eq 0 ]; then
        fail "AC-03-09 (c): MemoryMax=24M unexpectedly succeeded — Argon2id 64 MiB should have failed to allocate" \
             "out=$OUT_NEG stderr=$(head -c 400 "$WORK/cg_neg.err")"
    elif grep -qiE "cannot allocate memory|enomem|argon2|alloc" "$WORK/cg_neg.err"; then
        pass "AC-03-09 (c): clean ENOMEM-flavored fail under MemoryMax=24M (rc=$RC_NEG)"
    else
        fail "AC-03-09 (c): rc=$RC_NEG but stderr is not ENOMEM-flavored — kcap3 dispatch may be smashing errno" \
             "stderr=$(head -c 400 "$WORK/cg_neg.err")"
    fi
fi

banner "Top-level Makefile"

cd "$SCRIPT_DIR"
if make clean >/dev/null 2>&1 && make 2>"$WORK/make.log"; then
    pass "Top-level 'make' succeeds"
else
    fail "Top-level 'make'" "$(tail -5 "$WORK/make.log")"
fi

if make clean >/dev/null 2>&1; then
    pass "Top-level 'make clean' succeeds"
else
    fail "Top-level 'make clean'" "clean failed"
fi

# ── AC-01-F-05: no compiled artifacts left in source tree after make clean ──
LEFT=$(find "$SCRIPT_DIR/ephrun" "$SCRIPT_DIR/keypush" -maxdepth 1 -type f -executable \
       \( -not -name '*.sh' -not -name '*.c' -not -name '*.h' \) 2>/dev/null | tr '\n' ' ')
if [ -z "$LEFT" ]; then
    pass "AC-01-F-05: no compiled artifacts after make clean"
else
    fail "AC-01-F-05: compiled artifacts remain" "$LEFT"
fi

# ============================================================================
# Summary
# ============================================================================

banner "Test Summary"

TOTAL=$((PASS + FAIL))
echo ""
echo "  Total:  $TOTAL"
echo "  $(green "Passed: $PASS")"
if [ "$FAIL" -gt 0 ]; then
    echo "  $(red "Failed: $FAIL")"
    echo ""
    echo "  Failed tests:"
    for t in "${TESTS[@]}"; do
        if [[ "$t" == FAIL:* ]]; then
            echo "    $(red "• ${t#FAIL: }")"
        fi
    done
else
    echo "  Failed: 0"
fi
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "$(red '  ✗ SOME TESTS FAILED')"
    exit 1
else
    echo "$(green '  ✓ ALL TESTS PASSED')"
    exit 0
fi
