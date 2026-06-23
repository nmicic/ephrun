# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.
#
# ephrun/ Makefile — builds all core tools
#
# Usage:
#   make                  # build all tools (Linux: full set, macOS: genkey/elfenc_pack/kcap_pack)
#   make STATIC=1         # static linking (for deployment to remote machines)
#   make clean            # remove binaries
#   make help             # show targets

UNAME_S := $(shell uname -s)

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c99 -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?=

# Static linking support
ifdef STATIC
  LDFLAGS += -static
endif

# Hardened linking on Linux
ifneq ($(UNAME_S),Darwin)
  ifndef STATIC
    LDFLAGS += -Wl,-z,relro,-z,now
  endif
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

# ---------- Cross-platform tools ----------
TOOLS = genkey elfenc_pack kcap_pack kcap_unpack hello

# ---------- Cross-platform tests ----------
TESTS = kcap_kdf_test

# ---------- Linux-only tools (require keyring) ----------
ifeq ($(UNAME_S),Linux)
  TOOLS += elfdec-run
  TESTS += test_key keyring_selftest keyring_crypto_test
endif

# ---------- Targets ----------
.PHONY: all tests check clean install-deps help

all: $(TOOLS)

tests: $(TESTS)

# Run cross-platform tests (kcap_kdf_test exercises the capsule format).
check: kcap_kdf_test
	./kcap_kdf_test

# --- Cross-platform ---

genkey: genkey.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

elfenc_pack: elfenc_pack.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

kcap_pack: kcap_pack.c kcap.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

kcap_unpack: kcap_unpack.c kcap.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

hello: hello.c
	$(CC) $(CFLAGS) -o $@ $<

kcap_kdf_test: kcap_kdf_test.c kcap.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

# --- Linux-only ---

elfdec-run: elfdec-run.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@ $< $(LDFLAGS) $(SODIUM_LIBS) -lkeyutils

test_key: test_key.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lkeyutils

keyring_selftest: keyring_selftest.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@ $< $(LDFLAGS) $(SODIUM_LIBS) -lkeyutils

keyring_crypto_test: keyring_crypto_test.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@ $< $(LDFLAGS) -lkeyutils -lssl -lcrypto

# ---------- Clean ----------
clean:
	rm -f $(TOOLS) $(TESTS)

# ---------- Install deps ----------
install-deps:
ifeq ($(UNAME_S),Linux)
	sudo apt-get install -y build-essential libsodium-dev libkeyutils-dev libssl-dev
else ifeq ($(UNAME_S),Darwin)
	brew install libsodium
else
	@echo "Unsupported OS — install libsodium manually"
endif

# ---------- Help ----------
help:
	@echo "Targets:"
	@echo "  all          - Build all tools (default)"
	@echo "  tests        - Build test utilities (Linux only)"
	@echo "  clean        - Remove all binaries"
	@echo "  install-deps - Install OS dependencies"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Options:"
	@echo "  STATIC=1     - Enable static linking"
	@echo ""
	@echo "Tools built:"
	@echo "  genkey elfenc_pack kcap_pack kcap_unpack hello"
ifeq ($(UNAME_S),Linux)
	@echo "  elfdec-run (Linux only)"
	@echo "  test_key keyring_selftest keyring_crypto_test (tests, Linux only)"
endif
