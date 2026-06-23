# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
#
# Top-level Makefile for ephrun
# Builds all core tools + keypush utilities

UNAME_S := $(shell uname -s)

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?=

# Hardened linking on Linux
ifneq ($(UNAME_S),Darwin)
  LDFLAGS += -Wl,-z,relro,-z,now
endif

# libsodium detection
PKG_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null)
PKG_LIBS   := $(shell pkg-config --libs   libsodium 2>/dev/null)

ifeq ($(PKG_LIBS),)
  ifeq ($(UNAME_S),Darwin)
    ifneq ("$(wildcard /opt/homebrew/include/)", "")
      CFLAGS += -I/opt/homebrew/include
      LDFLAGS += -L/opt/homebrew/lib
    else ifneq ("$(wildcard /usr/local/include/)", "")
      CFLAGS += -I/usr/local/include
      LDFLAGS += -L/usr/local/lib
    endif
  endif
  SODIUM_LIBS = -lsodium
else
  CFLAGS += $(PKG_CFLAGS)
  SODIUM_LIBS = $(PKG_LIBS)
endif

# ---------- Core tools (ephrun/) ----------
CORE_DIR   = ephrun
CORE_TOOLS = $(CORE_DIR)/genkey $(CORE_DIR)/elfenc_pack \
             $(CORE_DIR)/kcap_pack $(CORE_DIR)/kcap_unpack

# elfdec-run and tests require Linux keyring
ifeq ($(UNAME_S),Linux)
  CORE_TOOLS += $(CORE_DIR)/elfdec-run
  TEST_TOOLS  = $(CORE_DIR)/test_key $(CORE_DIR)/keyring_selftest
else
  TEST_TOOLS  =
endif

# ---------- Targets ----------
.PHONY: all core keypush clean install install-deps help

all: core keypush

core: $(CORE_TOOLS)

$(CORE_DIR)/genkey: $(CORE_DIR)/genkey.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

$(CORE_DIR)/elfenc_pack: $(CORE_DIR)/elfenc_pack.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

$(CORE_DIR)/kcap_pack: $(CORE_DIR)/kcap_pack.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

$(CORE_DIR)/kcap_unpack: $(CORE_DIR)/kcap_unpack.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

$(CORE_DIR)/elfdec-run: $(CORE_DIR)/elfdec-run.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@ $< $(LDFLAGS) $(SODIUM_LIBS) -lkeyutils

# Tests (Linux only)
$(CORE_DIR)/test_key: $(CORE_DIR)/test_key.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lkeyutils

$(CORE_DIR)/keyring_selftest: $(CORE_DIR)/keyring_selftest.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@ $< $(LDFLAGS) $(SODIUM_LIBS) -lkeyutils

tests: $(TEST_TOOLS)

# ---------- keypush (delegated) ----------
keypush:
	$(MAKE) -C keypush

# ---------- Install ----------
install: all
ifeq ($(UNAME_S),Linux)
	sudo install -o root -g root -m 0755 $(CORE_DIR)/elfdec-run /usr/local/bin/elfdec-run
	@echo "Installed elfdec-run to /usr/local/bin/"
else
	@echo "Install: elfdec-run requires Linux (skipped)"
endif

install-deps:
ifeq ($(UNAME_S),Linux)
	sudo apt-get install -y build-essential libsodium-dev libkeyutils-dev
else ifeq ($(UNAME_S),Darwin)
	brew install libsodium
else
	@echo "Unsupported OS — install libsodium manually"
endif

# ---------- Clean ----------
clean:
	rm -f $(CORE_TOOLS) $(TEST_TOOLS)
	$(MAKE) -C ephrun clean
	$(MAKE) -C keypush clean

# ---------- Help ----------
help:
	@echo "Targets:"
	@echo "  all          - Build core tools + keypush (default)"
	@echo "  core         - Build genkey, elfenc_pack, kcap_pack, kcap_unpack, elfdec-run"
	@echo "  keypush      - Build keypushd + keypush_send"
	@echo "  tests        - Build test utilities (Linux only)"
	@echo "  install      - Install elfdec-run to /usr/local/bin (Linux, requires sudo)"
	@echo "  install-deps - Install OS dependencies"
	@echo "  clean        - Remove all built binaries"
	@echo "  help         - Show this help"
