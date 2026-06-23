#!/usr/bin/env bash
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
#
# elfdec-ssh-pushkey — push exactly 32 raw bytes into @s, set perms+TTL, link @u
set -euo pipefail

usage(){ echo "usage: $0 -H user@host -l label -k keyfile [-t ttl]"; exit 2; }
HOST= LABEL= KEYFILE= TTL=300
while getopts "H:l:k:t:" o; do
  case $o in
    H) HOST=$OPTARG;;
    l) LABEL=$OPTARG;;
    k) KEYFILE=$OPTARG;;
    t) TTL=$OPTARG;;
    *) usage;;
  esac
done
[[ $HOST && $LABEL && $KEYFILE ]] || usage
[[ -f $KEYFILE ]] || { echo "keyfile not found: $KEYFILE" >&2; exit 1; }

# IMPORTANT: single ssh; its stdin is the key bytes
KEYID=$(
  ssh -T -o ClearAllForwardings=yes -o RequestTTY=no "$HOST" \
  "set -euo pipefail
   keyctl new_session >/dev/null 2>&1 || true            # ensure @s
   KEYID=\$(keyctl padd user 'elfdec:$LABEL' @s)         # reads from stdin
   keyctl setperm \"\$KEYID\" 0x3f030000                  # owner: view+read; possessor: all
   keyctl timeout \"\$KEYID\" $TTL >/dev/null || true     # TTL seconds
   keyctl link \"\$KEYID\" @u >/dev/null 2>&1 || true     # optional anchor in @u
   printf '%s' \"\$KEYID\"
  " < "$KEYFILE"
)

echo "Pushed KEYID=$KEYID to $HOST label='$LABEL' (TTL ${TTL}s)"
echo "Run: ELFDEC_KEYID=$KEYID /usr/local/bin/elfdec-run ./yourprog.elfenc"
