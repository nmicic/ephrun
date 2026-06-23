#!/bin/bash
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
gcc -O2 -D_GNU_SOURCE elfdec-run.c -lsodium -lkeyutils -o elfdec-run
sudo install -o root -g root -m 0755 elfdec-run /usr/local/bin/elfdec-run
sudo mkdir -p /etc/elfenc
sudo cp pub.bin /etc/elfenc/pub.bin
sudo cp priv.bin /etc/elfenc/priv.bin
sudo chmod 600 /etc/elfenc/priv.bin
