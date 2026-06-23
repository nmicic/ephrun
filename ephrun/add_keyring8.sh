#!/bin/sh
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
set -e
keyctl new_session >/dev/null 2>&1 || true
LABEL=prod/hello

KEYFILE="${KEYFILE:-/etc/elfenc/priv.bin}"
KEYID=$(keyctl padd user "elfdec:$LABEL" @s < "$KEYFILE")
keyctl setperm "$KEYID" 0x3f030000     # owner:view+read, possessor all
keyctl timeout "$KEYID" 300
keyctl link "$KEYID" @u || true        # optional persistence anchor

# Now run by ID (robust):
ELFDEC_KEYID=$KEYID ./elfdec-run ./hello.elfenc
export ELFDEC_KEYID=""
# Or by label (if @u/@s is in your search path):
ELFDEC_LABEL=$LABEL ./elfdec-run ./hello.elfenc
