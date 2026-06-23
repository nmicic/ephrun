#!/bin/bash
# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
echo ':elfenc:M::ELFENC1\000::/usr/local/bin/elfdec-run:P' | sudo tee /proc/sys/fs/binfmt_misc/register
# check it took:
cat /proc/sys/fs/binfmt_misc/elfenc
