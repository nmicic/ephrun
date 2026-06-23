/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 *
 * kcap_pack — Pack a 32-byte priv key into a KCAP3 capsule.
 *
 * Output format: KCAP3 binary (D-13). 64-byte header + 48-byte ciphertext.
 * KCAP1 / KCAP2 are read-only legacy formats; this tool no longer emits them.
 */
#define _GNU_SOURCE
#include <sodium.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* shared capsule definitions (endian helpers, kcap3_pack) */
#include "kcap.h"

/* read whole file; if path is NULL, read stdin */
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
      "Usage: %s --label <name> --code <string> [--ttl <sec>]\n"
      "          [--in <priv.bin>] [--out <capsule.bin>]\n"
      "Reads 32-byte secret (priv.bin) and writes a KCAP3 binary capsule.\n"
      "  --ttl  : accepted for CLI compat but ignored (TLV trailer not in v1)\n"
      "  --json : DEPRECATED, exits with error in KCAP3 (use binary).\n",
      prog);
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    const char *label = NULL, *code = NULL, *inpath = NULL, *outpath = NULL;
    int ttl_used = 0;

    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i], "--label") && i+1<argc) { label = argv[++i]; }
        else if (!strcmp(argv[i], "--code") && i+1<argc) { code = argv[++i]; }
        else if (!strcmp(argv[i], "--ttl") && i+1<argc) { (void)argv[++i]; ttl_used = 1; }
        else if (!strcmp(argv[i], "--in") && i+1<argc) { inpath = argv[++i]; }
        else if (!strcmp(argv[i], "--out") && i+1<argc) { outpath = argv[++i]; }
        else if (!strcmp(argv[i], "--json")) {
            fprintf(stderr, "JSON output deprecated in KCAP3; use binary.\n");
            return 2;
        }
        else { usage(argv[0]); return 2; }
    }
    if (!label || !code) { usage(argv[0]); return 2; }
    if (code[0] == '\0') { fprintf(stderr, "code required\n"); return 2; }

    if (ttl_used) {
        fprintf(stderr,
            "warning: --ttl ignored in KCAP3 (TLV trailer not implemented in v1)\n");
    }

    /* read 32-byte secret */
    unsigned char *priv = NULL; size_t plen = 0;
    if (read_all(inpath, &priv, &plen) != 0) return 1;
    if (plen != 32) {
        fprintf(stderr, "input must be exactly 32 bytes (got %zu)\n", plen);
        if (priv) { sodium_memzero(priv, plen); free(priv); }
        return 2;
    }

    /* Pack KCAP3. Output is exactly 64 + 48 = 112 bytes for raw priv[32]. */
    unsigned char outbuf[sizeof(struct kcap3_hdr) + 32 +
                         crypto_aead_xchacha20poly1305_ietf_ABYTES];
    size_t out_len = 0;
    if (kcap3_pack(code, priv, outbuf, sizeof outbuf, &out_len) != 0) {
        fprintf(stderr, "kcap3_pack failed (Argon2id memory pressure or AEAD error)\n");
        sodium_memzero(priv, 32);
        free(priv);
        sodium_memzero(outbuf, sizeof outbuf);
        return 1;
    }
    sodium_memzero(priv, 32);
    free(priv);

    /* Write output. Set 0600 mode on newly created files (AC-01-G-05). */
    FILE *out = NULL;
    if (outpath) {
        /* Open with restricted mode. fopen mode is implementation-defined,
           so use open() + fdopen() to set perms reliably. */
        int fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            perror("open out");
            sodium_memzero(outbuf, sizeof outbuf);
            return 1;
        }
        out = fdopen(fd, "wb");
        if (!out) {
            perror("fdopen out");
            close(fd);
            sodium_memzero(outbuf, sizeof outbuf);
            return 1;
        }
    } else {
        out = stdout;
    }

    if (fwrite(outbuf, 1, out_len, out) != out_len) {
        perror("write");
        if (outpath) fclose(out);
        sodium_memzero(outbuf, sizeof outbuf);
        return 1;
    }

    if (outpath) fclose(out);
    sodium_memzero(outbuf, sizeof outbuf);
    /* label is unused beyond CLI sanity (KCAP3 has no label field); intentional. */
    (void)label;
    return 0;
}
