#!/bin/bash
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
set -euo pipefail

export LABEL="prod/hello"
export KEYFILE="${KEYFILE:-/etc/elfenc/priv.bin}"

# Determine user context and capabilities
if [[ $EUID -eq 0 ]]; then
    echo "Running as root"
    KEYRING="@s"
    CAN_SET_TIMEOUT=true
    # Root can set more permissive permissions
    PERM=0x3f3f0000
else
    echo "Running as regular user"
    KEYRING="@u"
    CAN_SET_TIMEOUT=false
    # User needs read permission to access their own key
    PERM=0x3f010000  # This gives read access to owner
fi

# Ensure keyfile exists and is readable
if [[ ! -r $KEYFILE ]]; then
    echo "Error: $KEYFILE is missing or unreadable"
    exit 1
fi

echo "Adding key to keyring $KEYRING..."
RAW_ID=$(keyctl padd user "elfdec:${LABEL}" "$KEYRING" < "$KEYFILE")
KEYID=$(printf '%s' "$RAW_ID" | tr -d '[:space:]')

echo "✓ Created key with ID: $KEYID"

# For non-root users, we need to set permissions that allow reading
if [[ $EUID -ne 0 ]]; then
    # Try different permission combinations for regular users
    PERMS_TO_TRY=(
        "0x3f010000"  # rwsrws--- with read for owner
        "0x1f010000"  # rws------ with read for owner
        "0x0f010000"  # r-s------ minimal with read
    )
    
    PERM_SET=false
    for perm in "${PERMS_TO_TRY[@]}"; do
        if keyctl setperm "$KEYID" "$perm" 2>/dev/null; then
            echo "✓ Permissions set to $perm"
            PERM_SET=true
            break
        fi
    done
    
    if [[ $PERM_SET == false ]]; then
        echo "⚠ Could not set any custom permissions"
    fi
else
    # Root user
    if keyctl setperm "$KEYID" "$PERM" 2>/dev/null; then
        echo "✓ Permissions set to $PERM"
    else
        echo "⚠ Could not set custom permissions"
    fi
fi

# Set timeout only if we have permission
if [[ $CAN_SET_TIMEOUT == true ]]; then
    if keyctl timeout "$KEYID" 300 2>/dev/null; then
        echo "✓ Timeout set to 300 seconds"
    else
        echo "⚠ Could not set timeout"
    fi
else
    echo "ℹ Timeout not set (key will persist until logout)"
fi

# Display results
echo
echo "Key details:"

# Try to get key size safely
KEY_SIZE="unknown"
if keyctl print "$KEYID" >/dev/null 2>&1; then
    KEY_SIZE="$(keyctl print "$KEYID" | wc -c) bytes"
elif [[ -r $KEYFILE ]]; then
    KEY_SIZE="$(wc -c < "$KEYFILE") bytes (from source file)"
fi

echo "Size: $KEY_SIZE"
keyctl describe "$KEYID"
echo
echo "Current keyring contents:"
keyctl list "$KEYRING"

# Test if the key is actually usable
echo
echo "Key accessibility test:"
if keyctl print "$KEYID" >/dev/null 2>&1; then
    echo "✓ Key is readable and accessible"
else
    echo "⚠ Key exists but content is not readable (this may be intentional for security)"
fi
