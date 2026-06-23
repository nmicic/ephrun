/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 *
 * libexec_key.h — Header-only key loading library for ephrun programs
 *
 * Provides a consistent interface for loading encryption keys from:
 *   1. --keyfile PATH    (binary file, reads exactly `size` bytes)
 *   2. --keyid ID        (Linux keyring, numeric key ID)
 *   3. --keylabel LABEL  (Linux keyring, search by "prefix:label")
 *   4. Environment var   (hex-encoded string)
 *   5. --capsule PATH + --code CODE  (KCAP3 binary capsule; KCAP2 + KCAP1 still readable)
 *
 * Usage:
 *   #define EXECKEY_IMPLEMENTATION    // in exactly ONE .c file
 *   #include "libexec_key.h"
 *
 *   // Option A: Auto-detect from argv (parses --keyfile/--keyid/--keylabel)
 *   unsigned char key[32];
 *   int key_loaded = execkey_load_argv(key, 32, "myapp", "MYAPP_KEY", argc, argv);
 *
 *   // Option B: Load from specific source
 *   execkey_load_file(key, 32, "/path/to/key.bin");
 *   execkey_load_keyid(key, 32, "827867509");
 *   execkey_load_label(key, 32, "myapp", "prod/service");
 *   execkey_load_env(key, 32, "MYAPP_KEY");
 *
 * Capsule support (optional, needs libsodium):
 *   #define EXECKEY_CAPSULE           // enable capsule decryption
 *   #define EXECKEY_IMPLEMENTATION
 *   #include "libexec_key.h"
 *
 *   // Capsule decryption (KCAP3 binary; KCAP2/KCAP1 binary or JSON readable)
 *   execkey_load_capsule_file(key, 32, "capsule.bin", "my-secret-code");
 *   execkey_load_capsule_keyring(key, 32, "myapp_caps", "prod/svc", "code");
 *
 *   // execkey_load_argv also recognises --capsule PATH + --code CODE
 *   // and --capslabel LABEL + --code CODE when EXECKEY_CAPSULE is defined.
 *
 * Keyring convention:
 *   Keys are stored as "prefix:label" in the Linux kernel keyring.
 *   Capsules are stored as "prefix_caps:label".
 *   Example: --keylabel prod/myapp with prefix "myapp" searches for
 *   "myapp:prod/myapp" in @s (session) then @u (user) keyring.
 *
 * No dependencies beyond libc — uses popen("keyctl ...") so no -lkeyutils.
 * Capsule mode requires libsodium (-lsodium).
 *
 * License: Same as parent project.
 */

#ifndef LIBEXEC_KEY_H
#define LIBEXEC_KEY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ---------- API declarations ---------- */

/* Load key from a binary file (reads exactly `size` bytes) */
static int execkey_load_file(unsigned char *key, size_t size, const char *path);

/* Load key from keyring by numeric ID (uses keyctl pipe) */
static int execkey_load_keyid(unsigned char *key, size_t size, const char *keyid_str);

/* Load key from keyring by label (searches @s then @u for "prefix:label") */
static int execkey_load_label(unsigned char *key, size_t size, const char *prefix, const char *label);

/* Load key from hex-encoded environment variable */
static int execkey_load_env(unsigned char *key, size_t size, const char *envvar);

#ifdef EXECKEY_CAPSULE
#include <sodium.h>

/* Load key from a KCAP3 capsule file (binary) or legacy KCAP2/KCAP1 (binary or JSON) + code */
static int execkey_load_capsule_file(unsigned char *key, size_t size,
                                     const char *capsule_path, const char *code);

/* Load capsule from keyring ("prefix_caps:label") and decrypt with code */
static int execkey_load_capsule_keyring(unsigned char *key, size_t size,
                                        const char *caps_prefix, const char *label,
                                        const char *code);
#endif

/*
 * Auto-detect key source from argv.
 * Scans for --keyfile, --keyid, --keylabel in argv.
 * If EXECKEY_CAPSULE: also scans for --capsule/--capslabel + --code.
 * Falls back to envvar if set and nothing found in argv.
 *
 * Parameters:
 *   key      - output buffer
 *   size     - key size in bytes (e.g. 32)
 *   prefix   - keyring prefix for --keylabel (e.g. "myapp", "service")
 *   envvar   - environment variable name for hex key fallback (e.g. "MYAPP_KEY")
 *   argc     - from main()
 *   argv     - from main()
 *
 * Returns: 0 on success, -1 if no key found/loaded
 */
static int execkey_load_argv(unsigned char *key, size_t size,
                             const char *prefix, const char *envvar,
                             int argc, char **argv);

/* ---------- Implementation ---------- */

#ifdef EXECKEY_IMPLEMENTATION

static int execkey_load_file(unsigned char *key, size_t size, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "execkey: cannot open keyfile: %s\n", path);
        return -1;
    }
    size_t n = fread(key, 1, size, fp);
    fclose(fp);
    if (n != size) {
        fprintf(stderr, "execkey: keyfile must be exactly %zu bytes (got %zu): %s\n", size, n, path);
        return -1;
    }
    return 0;
}

/* validate string contains only safe characters for shell arguments */
static int execkey__is_safe_shell_arg(const char *s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        /* allow alphanumeric, dash, underscore, dot, slash, colon */
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '/' || c == ':') continue;
        return 0;
    }
    return 1;
}

static int execkey_load_keyid(unsigned char *key, size_t size, const char *keyid_str) {
    /* validate keyid is purely numeric (or numeric returned by keyctl search) */
    for (const char *p = keyid_str; *p; p++) {
        if (*p < '0' || *p > '9') {
            fprintf(stderr, "execkey: invalid keyid (must be numeric): %s\n", keyid_str);
            return -1;
        }
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "keyctl pipe %s 2>/dev/null", keyid_str);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "execkey: cannot execute keyctl\n");
        return -1;
    }
    size_t n = fread(key, 1, size, fp);
    int status = pclose(fp);

    if (status != 0 || n != size) {
        fprintf(stderr, "execkey: failed to read key from keyring ID %s (got %zu/%zu bytes)\n",
                keyid_str, n, size);
        return -1;
    }
    return 0;
}

static int execkey_load_label(unsigned char *key, size_t size, const char *prefix, const char *label) {
    /* Reject shell metacharacters in prefix/label to prevent injection */
    if (!execkey__is_safe_shell_arg(prefix) || !execkey__is_safe_shell_arg(label)) {
        fprintf(stderr, "execkey: prefix/label contains unsafe characters\n");
        return -1;
    }

    /* Search @s then @u for "prefix:label" */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "keyctl search @s user '%s:%s' 2>/dev/null || "
             "keyctl search @u user '%s:%s' 2>/dev/null",
             prefix, label, prefix, label);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "execkey: cannot execute keyctl\n");
        return -1;
    }

    char keyid_buf[32] = {0};
    if (!fgets(keyid_buf, sizeof(keyid_buf), fp)) {
        pclose(fp);
        fprintf(stderr, "execkey: key '%s:%s' not found in keyring (@s or @u)\n", prefix, label);
        return -1;
    }
    int status = pclose(fp);
    if (status != 0) {
        fprintf(stderr, "execkey: key '%s:%s' not found in keyring (@s or @u)\n", prefix, label);
        return -1;
    }

    /* Trim trailing newline */
    size_t len = strlen(keyid_buf);
    if (len > 0 && keyid_buf[len-1] == '\n') keyid_buf[len-1] = '\0';

    /* Pipe the key bytes using the found ID */
    return execkey_load_keyid(key, size, keyid_buf);
}

static int execkey_load_env(unsigned char *key, size_t size, const char *envvar) {
    const char *hex = getenv(envvar);
    if (!hex) return -1;

    size_t expected = size * 2;
    size_t len = strlen(hex);
    if (len != expected) {
        fprintf(stderr, "execkey: %s must be %zu hex chars (got %zu)\n", envvar, expected, len);
        return -1;
    }

    for (size_t i = 0; i < size; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%2x", &byte) != 1) {
            fprintf(stderr, "execkey: invalid hex in %s at position %zu\n", envvar, i*2);
            return -1;
        }
        key[i] = (unsigned char)byte;
    }
    return 0;
}

/* ===== Capsule support (requires libsodium) ===== */

#ifdef EXECKEY_CAPSULE

/* Use shared definitions from kcap.h */
#include "kcap.h"

/* Aliases for naming consistency */
#define execkey__get_le64    kcap_get_le64
#define execkey__get_le32    kcap_get_le32
#define execkey__derive_k    kcap_derive_k     /* legacy KCAP1 KDF */
#define execkey__derive_k_v2 kcap_derive_k_v2  /* KCAP2 Argon2id KDF */
#define execkey__kcap_hdr    kcap_bin_hdr

/* micro JSON helpers */
static int execkey__b64_to_buf(const char *b64, unsigned char *out, size_t outmax, size_t *outlen) {
    size_t bin_len = 0;
    if (sodium_base642bin(out, outmax, b64, strlen(b64), NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) return -1;
    *outlen = bin_len; return 0;
}

static int execkey__json_get_b64(const char *js, const char *jkey,
                                  unsigned char *out, size_t outmax, size_t *outlen) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", jkey);
    const char *p = strstr(js, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':'); if (!p) return -1;
    p++; /* skip past ':' */
    while (*p==' '||*p=='\t') p++;
    if (*p!='"') return -1;
    p++;
    const char *q = strchr(p, '"'); if (!q) return -1;
    char *tmp = strndup(p, (size_t)(q-p));
    if (!tmp) return -1;
    int rc = execkey__b64_to_buf(tmp, out, outmax, outlen);
    free(tmp);
    return rc;
}

static int execkey__json_get_u64(const char *js, const char *jkey, uint64_t *val) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", jkey);
    const char *p = strstr(js, pat); if (!p) return -1;
    p = strchr(p + strlen(pat), ':'); if (!p) return -1; p++;
    while (*p==' '||*p=='\t') p++;
    char *endp=NULL; unsigned long long v = strtoull(p, &endp, 10);
    if (endp==p) return -1; *val=(uint64_t)v; return 0;
}

static int execkey__json_get_u32(const char *js, const char *jkey, uint32_t *val) {
    uint64_t v=0; if (execkey__json_get_u64(js,jkey,&v)!=0) return -1; *val=(uint32_t)v; return 0;
}

/* Read entire file into malloc'd buffer */
static int execkey__read_file(const char *path, unsigned char **buf, size_t *len) {
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long L = ftell(f); if (L < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    unsigned char *p = (unsigned char*)malloc((size_t)L);
    if (!p) { fclose(f); return -1; }
    if (fread(p, 1, (size_t)L, f) != (size_t)L) { free(p); fclose(f); return -1; }
    fclose(f);
    *buf = p; *len = (size_t)L;
    return 0;
}

/* Decrypt capsule buffer (KCAP3 binary, KCAP2/KCAP1 binary or legacy JSON) → key[size]
 *
 * Dispatch on the first 5 bytes of `buf`:
 *   "KCAP" + 0x01      → KCAP3 (current primary, family-magic format)
 *   "KCAP" + '1' (0x31)→ KCAP1 legacy 7-byte magic ("KCAP1\0")
 *   "KCAP" + '2' (0x32)→ KCAP2 legacy 7-byte magic ("KCAP2\0")
 *   '{'                → legacy JSON capsule (KCAP1/KCAP2 only)
 *
 * KCAP3 has no JSON variant — JSON KCAP3 is rejected explicitly.
 */
static int execkey__decrypt_capsule(const char *code, const unsigned char *buf, size_t blen,
                                     unsigned char *out_key, size_t key_size) {
    time_t now = time(NULL);

    /* KCAP3 (family magic "KCAP" + version 0x01) */
    if (blen >= sizeof(struct kcap3_hdr) &&
        memcmp(buf, KCAP_FAMILY_MAGIC, 4) == 0 &&
        buf[4] == KCAP_FAMILY_VERSION) {
        if (key_size != 32) {
            fprintf(stderr, "execkey: KCAP3 capsules carry 32-byte priv only (got key_size=%zu)\n",
                    key_size);
            return -1;
        }
        unsigned char priv[32];
        if (kcap3_unpack(buf, blen, code, priv) != 0) {
            sodium_memzero(priv, sizeof priv);
            fprintf(stderr, "execkey: KCAP3 capsule decrypt failed (wrong code, bad params, or tampered)\n");
            return -1;
        }
        memcpy(out_key, priv, 32);
        sodium_memzero(priv, sizeof priv);
        return 0;
    }

    /* Binary KCAP1/KCAP2 (legacy 7-byte magic) */
    if (blen >= sizeof(struct execkey__kcap_hdr)) {
        const struct execkey__kcap_hdr *H = (const struct execkey__kcap_hdr*)buf;
        int is_v2 = (memcmp(H->magic, "KCAP2\0", 7) == 0);
        int is_v1 = (memcmp(H->magic, "KCAP1\0", 7) == 0);
        if (is_v1 || is_v2) {
            uint32_t ct_len = execkey__get_le32(H->ct_len);
            if (sizeof(*H) + (size_t)ct_len != blen) return -1;
            uint64_t cap_t0  = execkey__get_le64(H->t0);
            uint32_t cap_ttl = execkey__get_le32(H->ttl);
            if (cap_ttl && (uint64_t)now > cap_t0 + cap_ttl) {
                fprintf(stderr, "execkey: capsule TTL expired\n");
                return -1;
            }
            unsigned char K[32];
            if (is_v2) {
                if (execkey__derive_k_v2(code, H->salt, K) != 0) {
                    fprintf(stderr, "execkey: Argon2id KDF failed (memory pressure?)\n");
                    return -1;
                }
            } else {
                execkey__derive_k(code, H->salt, K);
            }
            unsigned char plain[256]; /* max key size we support */
            if (key_size > sizeof(plain)) { sodium_memzero(K,32); return -1; }
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plain, NULL, NULL,
                    buf + sizeof(*H), ct_len,
                    NULL, 0,
                    H->nonce, K) != 0) {
                sodium_memzero(K, 32);
                fprintf(stderr, "execkey: capsule decrypt failed (wrong code?)\n");
                return -1;
            }
            sodium_memzero(K, 32);
            memcpy(out_key, plain, key_size);
            sodium_memzero(plain, sizeof plain);
            return 0;
        }
    }

    /* JSON capsule fallback (legacy KCAP1/KCAP2 only — KCAP3 is binary-only). */
    if (blen > 0 && buf[0] == '{') {
        const char *js = (const char*)buf;
        unsigned char salt[16], nonce[24], ct[4096];
        size_t sl=0, nl=0, cl=0;
        uint64_t t0=0; uint32_t ttl=0; uint32_t v=2;
        if (execkey__json_get_b64(js,"salt",salt,sizeof salt,&sl)!=0 || sl!=16) return -1;
        if (execkey__json_get_b64(js,"nonce",nonce,sizeof nonce,&nl)!=0 || nl!=24) return -1;
        if (execkey__json_get_b64(js,"ct",ct,sizeof ct,&cl)!=0 || cl<16) return -1;
        (void)execkey__json_get_u64(js,"t0",&t0);
        (void)execkey__json_get_u32(js,"ttl",&ttl);
        (void)execkey__json_get_u32(js,"v",&v);
        /* KCAP3 is binary-only; JSON v >= 3 (or any non-1/2 value) rejected. */
        if (v != 1 && v != 2) {
            fprintf(stderr, "execkey: KCAP3 JSON not supported (v=%u)\n", v);
            return -1;
        }
        if (ttl && (uint64_t)now > t0 + ttl) {
            fprintf(stderr, "execkey: capsule TTL expired\n");
            return -1;
        }
        unsigned char K[32];
        if (v == 1) {
            execkey__derive_k(code, salt, K);
        } else {
            if (execkey__derive_k_v2(code, salt, K) != 0) {
                fprintf(stderr, "execkey: Argon2id KDF failed (memory pressure?)\n");
                return -1;
            }
        }
        unsigned char plain[256];
        if (key_size > sizeof(plain)) { sodium_memzero(K,32); return -1; }
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                plain, NULL, NULL,
                ct, cl,
                NULL, 0,
                nonce, K) != 0) {
            sodium_memzero(K, 32);
            fprintf(stderr, "execkey: capsule decrypt failed (wrong code?)\n");
            return -1;
        }
        sodium_memzero(K, 32);
        memcpy(out_key, plain, key_size);
        sodium_memzero(plain, sizeof plain);
        return 0;
    }

    fprintf(stderr, "execkey: unrecognized capsule format\n");
    return -1;
}

static int execkey_load_capsule_file(unsigned char *key, size_t size,
                                     const char *capsule_path, const char *code) {
    unsigned char *buf = NULL;
    size_t blen = 0;
    if (execkey__read_file(capsule_path, &buf, &blen) != 0) {
        fprintf(stderr, "execkey: cannot read capsule: %s\n", capsule_path);
        return -1;
    }
    int rc = execkey__decrypt_capsule(code, buf, blen, key, size);
    sodium_memzero(buf, blen);
    free(buf);
    return rc;
}

static int execkey_load_capsule_keyring(unsigned char *key, size_t size,
                                        const char *caps_prefix, const char *label,
                                        const char *code) {
    /* Reject shell metacharacters to prevent injection */
    if (!execkey__is_safe_shell_arg(caps_prefix) || !execkey__is_safe_shell_arg(label)) {
        fprintf(stderr, "execkey: capsule prefix/label contains unsafe characters\n");
        return -1;
    }

    /* Search keyring for "caps_prefix:label", read capsule bytes, decrypt */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "keyctl search @s user '%s:%s' 2>/dev/null || "
             "keyctl search @u user '%s:%s' 2>/dev/null",
             caps_prefix, label, caps_prefix, label);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char keyid_buf[32] = {0};
    if (!fgets(keyid_buf, sizeof(keyid_buf), fp)) { pclose(fp); return -1; }
    int status = pclose(fp);
    if (status != 0) return -1;

    size_t len = strlen(keyid_buf);
    if (len > 0 && keyid_buf[len-1] == '\n') keyid_buf[len-1] = '\0';

    /* Read capsule bytes via keyctl pipe */
    char pipe_cmd[256];
    snprintf(pipe_cmd, sizeof(pipe_cmd), "keyctl pipe %s 2>/dev/null", keyid_buf);
    fp = popen(pipe_cmd, "r");
    if (!fp) return -1;

    unsigned char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf), fp);
    status = pclose(fp);
    if (status != 0 || n == 0) return -1;

    int rc = execkey__decrypt_capsule(code, buf, n, key, size);
    sodium_memzero(buf, n);
    return rc;
}

#endif /* EXECKEY_CAPSULE */

static int execkey_load_argv(unsigned char *key, size_t size,
                             const char *prefix, const char *envvar,
                             int argc, char **argv) {
    /* Scan argv for --keyfile, --keyid, --keylabel */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--keyfile") && i+1 < argc) {
            return execkey_load_file(key, size, argv[i+1]);
        }
        if (!strcmp(argv[i], "--keyid") && i+1 < argc) {
            return execkey_load_keyid(key, size, argv[i+1]);
        }
        if (!strcmp(argv[i], "--keylabel") && i+1 < argc) {
            return execkey_load_label(key, size, prefix, argv[i+1]);
        }
    }

#ifdef EXECKEY_CAPSULE
    /* Scan for --capsule/--capslabel + --code */
    const char *code = NULL;
    const char *capsule_path = NULL;
    const char *caps_label = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--code") && i+1 < argc) code = argv[i+1];
        if (!strcmp(argv[i], "--capsule") && i+1 < argc) capsule_path = argv[i+1];
        if (!strcmp(argv[i], "--capslabel") && i+1 < argc) caps_label = argv[i+1];
    }
    /* Also check CODE env var as code fallback */
    if (!code) code = getenv("EXECKEY_CODE");

    if (code && capsule_path) {
        return execkey_load_capsule_file(key, size, capsule_path, code);
    }
    if (code && caps_label) {
        /* Capsule prefix convention: prefix + "_caps" */
        char caps_pfx[64];
        snprintf(caps_pfx, sizeof(caps_pfx), "%s_caps", prefix);
        return execkey_load_capsule_keyring(key, size, caps_pfx, caps_label, code);
    }
#endif

    /* Fallback: environment variable */
    if (envvar && envvar[0]) {
        return execkey_load_env(key, size, envvar);
    }

    return -1;  /* no key found */
}

#endif /* EXECKEY_IMPLEMENTATION */
#endif /* LIBEXEC_KEY_H */
