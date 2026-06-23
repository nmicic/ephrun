#!/bin/bash
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
# ============================================================================
# entrypoint-keypushd.sh — Wait for key delivery, then execute
#
# 1. Starts keypushd (prints bootstrap JSON to stdout)
# 2. Waits for key to arrive in kernel keyring
# 3. Executes the encrypted binary via elfdec-run
#
# Environment variables:
#   KEYPUSHD_PORT   UDP port (default: 9999)
#   KEYPUSHD_LABEL  Key label (default: prod/myapp)
#   KEYPUSHD_TTL    Key TTL seconds (default: 300)
#   KEYPUSHD_BIND   Bind address (default: 0.0.0.0)
# ============================================================================

set -euo pipefail

PORT="${KEYPUSHD_PORT:-9999}"
LABEL="${KEYPUSHD_LABEL:-prod/myapp}"
TTL="${KEYPUSHD_TTL:-300}"
BIND="${KEYPUSHD_BIND:-0.0.0.0}"
ELFENC="${1:-/app/hello.elfenc}"
shift 2>/dev/null || true

echo "=== keypushd starting ===" >&2
echo "Waiting for key delivery on ${BIND}:${PORT}/udp" >&2
echo "Label: ${LABEL}  TTL: ${TTL}s" >&2
echo "" >&2

# Start keypushd in foreground — it handles one key delivery then exits.
# Bootstrap JSON goes to stdout so the operator can see it.
keypushd --bind "$BIND" --port "$PORT" --label "$LABEL" --ttl "$TTL"

echo "" >&2
echo "=== Key received — executing encrypted binary ===" >&2

# Key is now in session keyring with label "elfdec:<LABEL>"
exec env ELFDEC_LABEL="$LABEL" elfdec-run "$ELFENC" "$@"
