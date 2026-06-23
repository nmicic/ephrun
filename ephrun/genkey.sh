#!/bin/bash
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
gcc -O2 genkey.c -lsodium -o genkey
./genkey
