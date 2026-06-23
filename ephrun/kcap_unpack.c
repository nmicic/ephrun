/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 *
 * kcap_unpack — Decrypt a KCAP3 capsule and emit priv[32] to stdout.
 *
 * Cross-platform (macOS + Linux). No keyring dependency.
 *
 * Usage:
 *   kcap_unpack --in <capsule.bin> --code <passphrase>
 *   KCAP_CODE=<passphrase> kcap_unpack --in <capsule.bin>
 *
 * Used as a test / fixture-verification tool. Not deployed in production
 * (elfdec-run consumes capsules in-process).
 *
 * Exit codes:
 *   0  success — 32 bytes of priv written to stdout.
 *   1  I/O or runtime error.
 *   2  bad CLI usage / decrypt rejected (wrong code, bad params, AEAD fail).
 */
#define _POSIX_C_SOURCE 200809L
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kcap.h"

static int read_all(const char *path, unsigned char **buf, size_t *len) {
    FILE *f = path ? fopen(path, "rb") : stdin;
    if (!f) { perror("open input"); return -1; }
    unsigned char *out = NULL;
    size_t cap = 0, n = 0;
    for (;;) {
        if (n == cap) {
            size_t ncap = cap ? cap*2 : 4096;
            unsigned char *tmp = realloc(out, ncap);
            if (!tmp) { free(out); if (path) fclose(f); return -1; }
            out = tmp; cap = ncap;
        }
        size_t r = fread(out + n, 1, cap - n, f);
        n += r;
        if (r == 0) {
            if (ferror(f)) { perror("read"); free(out); if (path) fclose(f); return -1; }
            break;
        }
    }
    if (path) fclose(f);
    *buf = out; *len = n; return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
      "Usage: %s --in <capsule.bin> [--code <passphrase>]\n"
      "  If --code is absent, reads passphrase from $KCAP_CODE.\n"
      "  Writes 32 bytes of decrypted priv key to stdout on success.\n",
      prog);
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    const char *inpath = NULL, *code = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--in") && i+1 < argc) { inpath = argv[++i]; }
        else if (!strcmp(argv[i], "--code") && i+1 < argc) { code = argv[++i]; }
        else { usage(argv[0]); return 2; }
    }
    if (!inpath) { usage(argv[0]); return 2; }
    if (!code) code = getenv("KCAP_CODE");
    if (!code || !code[0]) {
        fprintf(stderr, "kcap_unpack: --code or $KCAP_CODE required\n");
        return 2;
    }

    unsigned char *buf = NULL; size_t blen = 0;
    if (read_all(inpath, &buf, &blen) != 0) return 1;

    /* Reject anything not KCAP3 — this tool is KCAP3-only on purpose
       (we want a small, single-format reference reader for fixture checks). */
    if (blen < sizeof(struct kcap3_hdr) ||
        memcmp(buf, KCAP_FAMILY_MAGIC, 4) != 0 ||
        buf[4] != KCAP_FAMILY_VERSION) {
        fprintf(stderr, "kcap_unpack: not a KCAP3 capsule\n");
        sodium_memzero(buf, blen);
        free(buf);
        return 2;
    }

    unsigned char priv[32];
    int rc = kcap3_unpack(buf, blen, code, priv);
    sodium_memzero(buf, blen);
    free(buf);
    if (rc != 0) {
        fprintf(stderr, "kcap_unpack: decrypt failed (wrong code, bad params, or tampered)\n");
        sodium_memzero(priv, sizeof priv);
        return 2;
    }

    if (fwrite(priv, 1, 32, stdout) != 32) {
        perror("write stdout");
        sodium_memzero(priv, sizeof priv);
        return 1;
    }
    sodium_memzero(priv, sizeof priv);
    return 0;
}
