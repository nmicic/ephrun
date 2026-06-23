# Copyright (c) 2025 Nenad Micic <nenad@micic.be>
# Licensed under the Apache License, Version 2.0. See LICENSE file for details.

UNAME_S := $(shell uname -s)

CC ?= cc
CFLAGS ?= -O2 -pipe -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?=

# ---------- libsodium (common to both targets) ----------
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

# Hardened linking on platforms that support it
ifneq ($(UNAME_S),Darwin)
  LDFLAGS += -Wl,-z,relro,-z,now
endif

# ---------- Targets ----------
# keypushd requires Linux keyring (libkeyutils) — skip on macOS
# keypush_send is cross-platform (Linux + macOS)

ifeq ($(UNAME_S),Linux)
  ALL_TARGETS = keypushd keypush_send
else
  ALL_TARGETS = keypush_send
endif

.PHONY: all clean help

all: $(ALL_TARGETS)

keypushd: keypushd.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS) -lkeyutils

keypush_send: keypush_send.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SODIUM_LIBS)

clean:
	rm -f keypushd keypush_send

help:
	@echo "Targets:"
	@echo "  all          - Build keypushd (Linux only) + keypush_send"
	@echo "  keypushd     - UDP key receiver daemon (Linux, needs libkeyutils)"
	@echo "  keypush_send - UDP key sender (cross-platform)"
	@echo "  clean        - Remove binaries"
