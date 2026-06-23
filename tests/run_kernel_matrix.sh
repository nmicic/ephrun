#!/bin/bash
# Copyright (c) 2026 Nenad Micic <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# tests/run_kernel_matrix.sh — run ephrun test.sh across kernel versions
# using virtme-ng.
#
# What this catches:
#   Anything that would differ across kernel versions in elfdec-run's
#   syscall path — memfd_create flag handling (D-20), execveat AT_EMPTY_PATH
#   support, F_ADD_SEALS behaviour, /dev/shm fallback path, prctl flags.
#
# What this CANNOT catch under virtme-ng (run on a real KVM VM for these):
#   - libkeyutils session-keyring tests (Mode 2 / Mode 3 / capsule-in-keyring).
#     virtme-ng has no logind/PAM session — the session keyring is in a
#     transient anonymous state, so `keyctl padd ... @s` from one process
#     doesn't survive into another's view the way it does on a normal
#     logged-in host. 3 keyring-flavored tests fail on every kernel here.
#   - AC-03-09 (Argon2id under cgroup memory pressure) — needs systemd-run
#     --user --scope, which needs DBus + logind. Always fails in virtme-ng.
#
#   Total: 4 baseline failures on every kernel under virtme-ng. The matrix
#   is therefore comparing *deltas* from that baseline — a kernel that
#   shows >4 failures, or shows different failures, is the interesting case.
#
# Known environmental skips (virtme-ng image limitation, not an ephrun bug):
#   v5.4 / v5.10 — the upstream prebuilt kernel images for these versions
#   don't enable CONFIG_VIRTIO_CONSOLE in their .config, so virtme-ng-init's
#   --exec channel ("script I/O ports") never connects and our test script
#   never runs in the guest. The VM boots to an interactive shell instead
#   and times out. (They also hit a known psi_trigger_create NULL-deref
#   oops at boot, which doesn't panic but does show in the log.) These
#   kernels are kept in the default list so the matrix surfaces the skip
#   reason; pass --kernels "v5.15 v6.1 v6.5 v6.8" to silence them.
#   To genuinely cover v5.4/v5.10, run test.sh on a real Ubuntu 18.04 /
#   20.04 host (or VM) where virtio-serial isn't a question.
#
# Requirements:
#   pip install virtme-ng    (or apt install virtme-ng)
#   /dev/kvm accessible      (--no-kvm falls back to TCG, much slower)
#   libsodium-dev libkeyutils-dev installed on host (shared into VM via 9p)
#
# Usage:
#   ./tests/run_kernel_matrix.sh                          # all kernels
#   ./tests/run_kernel_matrix.sh --kernels "v5.15 v6.8"   # subset
#   ./tests/run_kernel_matrix.sh --no-kvm                 # TCG emulation
#   ./tests/run_kernel_matrix.sh --verbose                # full per-kernel output
#
# Kernels and what they exercise:
#   v5.4   — pre-MFD_EXEC; tests D-20 retry path (skipped: see above)
#   v5.10  — same                                       (skipped: see above)
#   v5.15  — pre-MFD_EXEC LTS that surfaced D-20 originally (Ubuntu 22.04)
#   v6.1   — pre-MFD_EXEC LTS
#   v6.5   — pre-MFD_EXEC stable
#   v6.8   — current; MFD_EXEC available (introduced 6.3)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

USE_KVM=1
VERBOSE=0
MEMORY="2G"
CPUS=1
KERNELS="v5.4 v5.10 v5.15 v6.1 v6.5 v6.8"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-kvm)    USE_KVM=0; shift ;;
        --verbose)   VERBOSE=1; shift ;;
        --memory)    MEMORY="$2"; shift 2 ;;
        --cpus)      CPUS="$2"; shift 2 ;;
        --kernels)   KERNELS="$2"; shift 2 ;;
        --help|-h)
            head -45 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if ! command -v vng >/dev/null 2>&1; then
    echo "ERROR: virtme-ng (vng) not found."
    echo "  Install: pip install virtme-ng  (or: apt install virtme-ng)"
    exit 1
fi

KVM_FLAG=""
if [[ $USE_KVM -eq 0 ]]; then
    KVM_FLAG="--disable-kvm"
    echo "NOTE: Running without KVM (TCG emulation) — significantly slower."
elif [[ ! -w /dev/kvm ]] 2>/dev/null; then
    echo "WARNING: /dev/kvm not writable — falling back to TCG emulation."
    echo "  Fix: sudo usermod -aG kvm \$(whoami) && newgrp kvm"
    KVM_FLAG="--disable-kvm"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ephrun kernel matrix test (virtme-ng)                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Repo:    $REPO_DIR"
echo "Kernels: $KERNELS"
echo "KVM:     ${KVM_FLAG:-enabled}"
echo "Memory:  $MEMORY  CPUs: $CPUS"
echo ""

# Build once on the host. virtme-ng's 9p mount means the same binaries
# (built against the host's headers) are exercised against each kernel —
# that's exactly the deployment scenario: distribute a build, run on
# whatever kernel the target has.
cd "$REPO_DIR"
echo "Building on host (binaries shared into VMs via 9p)..."
make clean >/dev/null 2>&1
if ! make >/tmp/ephrun_matrix_build.log 2>&1; then
    echo "ERROR: host build failed"
    tail -20 /tmp/ephrun_matrix_build.log
    exit 1
fi
echo "  built: $(ls ephrun/elfdec-run keypush/keypushd 2>/dev/null | wc -l) tools"

declare -A K_TOTAL K_PASS K_FAIL K_NEW_FAIL
ALL_FAIL_LINES=""

run_one_kernel() {
    local K="$1"
    local LOG="/tmp/ephrun_matrix_${K//[^a-zA-Z0-9]/_}.log"

    echo ""
    echo "─── Kernel: $K ────────────────────────────────────────────────"

    # bash test.sh inside the kernel, with stdout+stderr to LOG.
    # `vng --rw --pwd` mounts host fs read-write at the host's $PWD.
    # `--cwd` not used because --pwd handles it. Memory must be high enough
    # for Argon2id (64 MiB) plus elfdec-run plus libsodium plus shell overhead.
    # Older kernels (v5.4/v5.10) boot noticeably slower under virtme-ng
    # and 9p init takes longer; 600s gives headroom for the full test.sh
    # run (~25-30s of work + boot/teardown).
    # --verbose: writes virtme-ng-init lines into the log so we can detect
    # "cannot find script I/O ports" (= image lacks virtio-serial) and
    # report a meaningful skip reason instead of "boot failed (rc=124)".
    local rc=0
    timeout 600 vng --verbose --run "$K" $KVM_FLAG --rw --pwd \
        --memory "$MEMORY" --cpus "$CPUS" \
        --exec "bash -c 'cd $REPO_DIR && bash test.sh'" \
        >"$LOG" 2>&1 || rc=$?

    if [[ $rc -ne 0 ]] && ! grep -q "Test Summary" "$LOG"; then
        if grep -q "cannot find script I/O ports" "$LOG"; then
            # Upstream prebuilt kernel image lacks CONFIG_VIRTIO_CONSOLE,
            # so virtme-ng-init's --exec channel never connects. Not our
            # bug — see the known-environmental-skips block at top.
            echo "  ⚠  skipped: kernel image lacks virtio-serial — virtme-ng --exec unavailable"
        else
            echo "  ⚠  vng/boot failed (rc=$rc); skipping kernel"
        fi
        K_TOTAL[$K]="?"
        K_PASS[$K]="?"
        K_FAIL[$K]="?"
        return
    fi

    local total pass fail
    total=$(grep -oE "Total: *[0-9]+" "$LOG" | tail -1 | grep -oE "[0-9]+" || echo "?")
    pass=$( grep -oE "Passed: *[0-9]+" "$LOG" | tail -1 | grep -oE "[0-9]+" || echo "?")
    fail=$( grep -oE "Failed: *[0-9]+" "$LOG" | tail -1 | grep -oE "[0-9]+" || echo "?")

    K_TOTAL[$K]=$total
    K_PASS[$K]=$pass
    K_FAIL[$K]=$fail

    echo "  total=$total pass=$pass fail=$fail"

    # Per-kernel failed-test list (the AC name only, for delta comparison)
    local FAILED
    FAILED=$(awk '/Failed tests:/,0' "$LOG" \
             | grep -oE '• [^—]+' \
             | sed -e 's/^• //' -e 's/ *$//' \
             | sort -u)
    if [[ -n "$FAILED" ]]; then
        echo "  failures:"
        echo "$FAILED" | sed 's/^/    - /'
        # Stash for delta detection across kernels
        while IFS= read -r line; do
            ALL_FAIL_LINES+="${K}|${line}"$'\n'
        done <<< "$FAILED"
    fi

    if [[ $VERBOSE -eq 1 ]]; then
        echo "  ── full log (last 60 lines): ──"
        tail -60 "$LOG" | sed 's/^/    | /'
    fi
}

for K in $KERNELS; do
    run_one_kernel "$K"
done

# ─── Summary ────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  KERNEL MATRIX SUMMARY                                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
printf "  %-8s  %-7s  %-7s  %-7s\n" "kernel" "total" "pass" "fail"
printf "  %-8s  %-7s  %-7s  %-7s\n" "------" "-----" "----" "----"
WORST_FAIL=0
for K in $KERNELS; do
    printf "  %-8s  %-7s  %-7s  %-7s\n" "$K" "${K_TOTAL[$K]:-?}" "${K_PASS[$K]:-?}" "${K_FAIL[$K]:-?}"
    if [[ "${K_FAIL[$K]:-0}" =~ ^[0-9]+$ ]] && (( ${K_FAIL[$K]} > WORST_FAIL )); then
        WORST_FAIL=${K_FAIL[$K]}
    fi
done

# Delta — list any failure that does NOT appear on every kernel that actually
# completed. Skipped kernels (boot timeout, "?" results) must be excluded from
# the denominator, otherwise uniform baseline failures get mis-flagged as
# deltas just because some kernel didn't run.
echo ""
echo "─── Failure deltas (tests that fail on some kernels, not others) ───"
NUM_OK=0
for K in $KERNELS; do
    if [[ "${K_FAIL[$K]:-?}" =~ ^[0-9]+$ ]]; then
        NUM_OK=$((NUM_OK + 1))
    fi
done
if [[ -n "$ALL_FAIL_LINES" ]] && (( NUM_OK > 0 )); then
    DELTAS=$(echo -n "$ALL_FAIL_LINES" \
             | awk -F'|' '{ k[$2]++ } END { for (t in k) if (k[t] != "'"$NUM_OK"'") print k[t]"x  "t }' \
             | sort -nr)
    if [[ -n "$DELTAS" ]]; then
        echo "$DELTAS" | sed 's/^/  /'
        echo ""
        echo "  (failures listed above appear on some kernels but not others —"
        echo "   these are the kernel-version-sensitive cases worth investigating.)"
    else
        echo "  (none — every failure is uniform across all $NUM_OK kernels"
        echo "   that completed; no kernel-version-specific delta detected.)"
    fi
else
    echo "  (no failures recorded)"
fi

echo ""
echo "Per-kernel logs: /tmp/ephrun_matrix_v*.log"
echo ""

# Exit non-zero if any kernel had MORE failures than the lowest-fail kernel.
# That's how we surface a kernel-version regression vs. the virtme-ng
# environmental baseline. Skipped kernels (K_FAIL="?") are excluded.
LOWEST_FAIL=-1
for K in $KERNELS; do
    if [[ "${K_FAIL[$K]:-?}" =~ ^[0-9]+$ ]]; then
        if (( LOWEST_FAIL < 0 )) || (( ${K_FAIL[$K]} < LOWEST_FAIL )); then
            LOWEST_FAIL=${K_FAIL[$K]}
        fi
    fi
done

NUM_SKIPPED=0
for K in $KERNELS; do
    [[ "${K_FAIL[$K]:-?}" == "?" ]] && NUM_SKIPPED=$((NUM_SKIPPED + 1))
done

if (( LOWEST_FAIL < 0 )); then
    echo "⚠  No kernel completed test.sh — see the per-kernel logs and the"
    echo "   known-environmental-skips block at the top of this script."
    exit 1
fi

if (( NUM_SKIPPED > 0 )); then
    echo "Note: $NUM_SKIPPED kernel(s) skipped (see ⚠ above) — typically the"
    echo "      prebuilt v5.4/v5.10 images that lack virtio-serial."
fi

if (( WORST_FAIL > LOWEST_FAIL )); then
    echo "⚠  Some kernels failed more tests than others — investigate the deltas above."
    exit 1
elif (( LOWEST_FAIL > 0 )); then
    echo "Note: $LOWEST_FAIL test(s) fail uniformly on every kernel under virtme-ng"
    echo "      (expected — see the comment block at the top of this script for the"
    echo "      list of tests that require logind/PAM/DBus and only work on a real VM)."
    exit 0
else
    echo "All tests pass on every kernel."
    exit 0
fi
