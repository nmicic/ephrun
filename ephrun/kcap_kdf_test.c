/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 *
 * kcap_kdf_test.c — KCAP capsule KDF round-trip + backward-read regression
 *                   + KCAP3 wire-format / AAD / param-policy tests.
 *
 * Build (driven by Makefile):
 *   gcc -O2 -Wall kcap_kdf_test.c -lsodium -o kcap_kdf_test
 *
 * AC coverage map (ACCEPTANCE_CRITERIA.md AC-01):
 *   A-01..A-10  wire format        — checked in kcap3_pack output
 *   B-01..B-08  KDF/AEAD/policy    — round-trip, AAD tamper, param floor/ceiling,
 *                                    wrong code, timing
 *   C-01..C-05  round-trip         — round-trip + truncated/oversized
 *   D-01..D-03  reference fixture  — testdata/kcap3.bin pinned
 *   E-01..E-02  backward read      — testdata/kcap1.bin + testdata/kcap2.bin
 *
 * The decrypt path mirrors decrypt_capsule_buffer() in elfdec-run.c (Linux-only).
 * elfdec-run.c itself pulls in Linux-only headers (keyutils, memfd) so this
 * test exercises the format-level invariants directly via kcap.h.
 */
#define _POSIX_C_SOURCE 200809L
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

#include "kcap.h"

#define KCAP1_FIXTURE_PATH "testdata/kcap1.bin"
#define KCAP1_FIXTURE_CODE "kcap1-fixture-code"
#define KCAP2_FIXTURE_PATH "testdata/kcap2.bin"
#define KCAP2_FIXTURE_CODE "kcap2-fixture-code"
#define KCAP3_FIXTURE_PATH "testdata/kcap3.bin"
#define KCAP3_FIXTURE_CODE "kcap3-fixture-code"

/* ===== Legacy KCAP1/KCAP2 decrypt (mirrors elfdec-run / libexec_key) ===== */
static int decrypt_kcap_legacy_buf(const char *code,
                                   const unsigned char *buf, size_t blen,
                                   unsigned char out[32]) {
    if (blen < sizeof(struct kcap_bin_hdr)) return -1;
    const struct kcap_bin_hdr *H = (const struct kcap_bin_hdr*)buf;
    int is_v2 = (memcmp(H->magic, "KCAP2\0", 7) == 0);
    int is_v1 = (memcmp(H->magic, "KCAP1\0", 7) == 0);
    if (!is_v1 && !is_v2) return -1;

    uint32_t ct_len = kcap_get_le32(H->ct_len);
    if (sizeof(*H) + (size_t)ct_len != blen) return -1;

    unsigned char K[32];
    if (is_v2) {
        if (kcap_derive_k_v2(code, H->salt, K) != 0) return -1;
    } else {
        kcap_derive_k(code, H->salt, K);
    }
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            out, NULL, NULL,
            buf + sizeof(*H), ct_len,
            NULL, 0,
            H->nonce, K);
    sodium_memzero(K, sizeof K);
    return rc;
}

/* ===== File helpers ===== */
static int read_file(const char *path, unsigned char **buf, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END); long L = ftell(f); fseek(f, 0, SEEK_SET);
    if (L < 0) { fclose(f); return -1; }
    unsigned char *p = malloc((size_t)L);
    if (!p) { fclose(f); return -1; }
    if (fread(p, 1, (size_t)L, f) != (size_t)L) { free(p); fclose(f); return -1; }
    fclose(f);
    *buf = p; *len = (size_t)L;
    return 0;
}

static int write_file(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int rc = (fwrite(buf, 1, len, f) == len) ? 0 : -1;
    fclose(f);
    return rc;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static double ms_since(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 +
           (b.tv_nsec - a.tv_nsec) / 1.0e6;
}

/* ===== Pinned-salt/nonce fixture generator =====
   The production kcap3_pack uses randombytes_buf for salt+nonce; for
   reproducible test fixtures we need pinned values. This helper builds a
   KCAP3 capsule with caller-supplied salt+nonce. Used only at fixture
   generation time. */
static int kcap3_pack_pinned(const char *passphrase,
                             const unsigned char priv[32],
                             const unsigned char salt[16],
                             const unsigned char nonce[24],
                             unsigned char *out_buf, size_t out_cap,
                             size_t *out_len) {
    const size_t ct_len = 32 + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    const size_t total = sizeof(struct kcap3_hdr) + ct_len;
    if (out_cap < total) return -1;

    struct kcap3_hdr H;
    memset(&H, 0, sizeof H);
    memcpy(H.magic, KCAP_FAMILY_MAGIC, 4);
    H.version    = KCAP_FAMILY_VERSION;
    H.project_id = KCAP_PROJECT_EPHRUN;
    H.flags      = kcap_put_le16(0);
    memcpy(H.salt, salt, 16);
    memcpy(H.nonce, nonce, 24);
    H.time_cost   = kcap_put_le32(KCAP3_DEFAULT_TIME_COST);
    H.mem_cost    = kcap_put_le32(KCAP3_DEFAULT_MEM_COST);
    H.parallelism = kcap_put_le32(KCAP3_DEFAULT_PARALLELISM);
    H.ct_len      = kcap_put_le32((uint32_t)ct_len);
    memcpy(out_buf, &H, sizeof H);

    unsigned char K[32];
    if (crypto_pwhash(K, 32,
                      passphrase, strlen(passphrase),
                      H.salt,
                      KCAP3_DEFAULT_TIME_COST,
                      (size_t)KCAP3_DEFAULT_MEM_COST * 1024u,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(K, sizeof K);
        return -1;
    }
    unsigned long long olen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out_buf + sizeof H, &olen,
            priv, 32,
            out_buf, sizeof H,
            NULL, H.nonce, K) != 0) {
        sodium_memzero(K, sizeof K);
        return -1;
    }
    sodium_memzero(K, sizeof K);
    *out_len = total;
    return 0;
}

/* Same shape, but builds a KCAP2 binary (legacy 7-byte magic header) with
   pinned salt+nonce. Used to deterministically materialize testdata/kcap2.bin
   so the post-change test runner can verify the legacy read path without
   shelling out to the pre-change kcap_pack binary. */
static int kcap2_pack_pinned(const char *code,
                             const unsigned char priv[32],
                             const unsigned char salt[16],
                             const unsigned char nonce[24],
                             unsigned char *out_buf, size_t out_cap,
                             size_t *out_len) {
    const size_t ct_len = 32 + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    const size_t total = sizeof(struct kcap_bin_hdr) + ct_len;
    if (out_cap < total) return -1;

    unsigned char K[32];
    if (kcap_derive_k_v2(code, salt, K) != 0) {
        sodium_memzero(K, sizeof K);
        return -1;
    }

    struct kcap_bin_hdr H = {0};
    memcpy(H.magic, "KCAP2\0", 7);
    H.t0 = kcap_put_le64(0);   /* pinned: no timestamp leak in fixture */
    H.ttl = kcap_put_le32(0);
    memcpy(H.salt, salt, 16);
    memcpy(H.nonce, nonce, 24);
    H.ct_len = kcap_put_le32((uint32_t)ct_len);
    memcpy(out_buf, &H, sizeof H);

    unsigned long long olen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out_buf + sizeof H, &olen,
            priv, 32,
            NULL, 0, NULL, H.nonce, K) != 0) {
        sodium_memzero(K, sizeof K);
        return -1;
    }
    sodium_memzero(K, sizeof K);
    *out_len = total;
    return 0;
}

/* ===== Test-only helper: pack a KCAP3 capsule with an out-of-policy param
   value, bypassing the pack-side defaults. Used to feed the receiver a
   capsule the real kcap3_pack would never produce, so we can prove the
   receiver-side D-15 policy gate fires before Argon2id runs. */
static int kcap3_pack_custom_params(const char *passphrase,
                                    const unsigned char priv[32],
                                    uint32_t time_cost, uint32_t mem_cost_kb,
                                    uint32_t parallelism,
                                    unsigned char *out_buf, size_t out_cap,
                                    size_t *out_len) {
    const size_t ct_len = 32 + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    const size_t total = sizeof(struct kcap3_hdr) + ct_len;
    if (out_cap < total) return -1;

    struct kcap3_hdr H;
    memset(&H, 0, sizeof H);
    memcpy(H.magic, KCAP_FAMILY_MAGIC, 4);
    H.version    = KCAP_FAMILY_VERSION;
    H.project_id = KCAP_PROJECT_EPHRUN;
    H.flags      = kcap_put_le16(0);
    randombytes_buf(H.salt,  sizeof H.salt);
    randombytes_buf(H.nonce, sizeof H.nonce);
    H.time_cost   = kcap_put_le32(time_cost);
    H.mem_cost    = kcap_put_le32(mem_cost_kb);
    H.parallelism = kcap_put_le32(parallelism);
    H.ct_len      = kcap_put_le32((uint32_t)ct_len);
    memcpy(out_buf, &H, sizeof H);

    /* Just put random ciphertext bytes in — receiver should reject on
       param policy BEFORE attempting AEAD, so the contents don't matter. */
    randombytes_buf(out_buf + sizeof H, ct_len);
    (void)passphrase;
    (void)priv;
    *out_len = total;
    return 0;
}

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } \
    fprintf(stderr, "ok:   %s\n", msg); \
} while (0)

int main(void) {
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    /* Reusable fixed priv = bytes(0..31). */
    unsigned char ref_priv[32];
    for (int i = 0; i < 32; i++) ref_priv[i] = (unsigned char)i;

    /* ===== 0. Sanity: kcap3_hdr is exactly 64 bytes ===== */
    CHECK(sizeof(struct kcap3_hdr) == 64, "kcap3_hdr is 64 bytes");

    /* ===== 1. KCAP3 round-trip with random salt+nonce ===== */
    {
        unsigned char buf[200];
        size_t blen = 0;
        CHECK(kcap3_pack(KCAP3_FIXTURE_CODE, ref_priv, buf, sizeof buf, &blen) == 0,
              "kcap3 pack random salt/nonce");
        CHECK(blen == 112, "kcap3 capsule is 112 bytes for raw priv[32]");
        CHECK(memcmp(buf, KCAP_FAMILY_MAGIC, 4) == 0, "kcap3 magic == 'KCAP'");
        CHECK(buf[4] == KCAP_FAMILY_VERSION, "kcap3 version == 0x01");
        CHECK(buf[5] == KCAP_PROJECT_EPHRUN, "kcap3 project_id == 0x01");
        /* flags bytes 6..7 must be zero in v1. */
        CHECK(buf[6] == 0 && buf[7] == 0, "kcap3 flags == 0 in v1");
        /* ct_len bytes 60..63 little-endian == 48 (= 32 priv + 16 tag). */
        uint32_t ctl;
        memcpy(&ctl, buf + 60, 4);
        CHECK(kcap_get_le32(ctl) == 48, "kcap3 ct_len == 48");

        unsigned char got[32];
        CHECK(kcap3_unpack(buf, blen, KCAP3_FIXTURE_CODE, got) == 0,
              "kcap3 unpack random salt/nonce");
        CHECK(memcmp(got, ref_priv, 32) == 0, "kcap3 round-trip bytes match");

        /* AC-01-B-05: wrong passphrase rejection. */
        unsigned char trash[32];
        int wrong_rc = kcap3_unpack(buf, blen, "not-the-code", trash);
        CHECK(wrong_rc != 0, "kcap3 rejects wrong passphrase");
    }

    /* ===== 2. AAD tamper attacks (AC-01-B-03 + B-04) =====
       For each field with assigned semantics we mutate one byte and verify
       the receiver rejects. */
    {
        unsigned char base[112];
        size_t blen = 0;
        CHECK(kcap3_pack(KCAP3_FIXTURE_CODE, ref_priv, base, sizeof base, &blen) == 0,
              "kcap3 pack for tamper baseline");
        CHECK(blen == 112, "tamper baseline is 112 bytes");

        unsigned char got[32];

        /* B-03: in-policy mutation of time_cost (3 -> 4, both inside D-15).
           Receiver MUST fail at AEAD, not at param policy. */
        {
            unsigned char tampered[112];
            memcpy(tampered, base, blen);
            uint32_t v = kcap_put_le32(4);
            memcpy(tampered + 24, &v, 4);
            int rc = kcap3_unpack(tampered, blen, KCAP3_FIXTURE_CODE, got);
            CHECK(rc != 0, "kcap3 AAD tamper time_cost (3->4, in policy) rejected by AEAD");
        }

        /* B-04: per-field one-byte flips. Each must be rejected. */
        const struct {
            size_t off;   /* byte offset to mutate */
            const char *name;
        } cases[] = {
            { 0,  "magic[0]" },
            { 3,  "magic[3]" },
            /* Note: byte 4 (version) and byte 5 (project_id) get rejected
               on the allowlist BEFORE any AEAD call, so we test them
               separately below. */
            { 8,  "salt[0]" },
            { 23, "salt[15]" },
            { 36, "nonce[0]" },
            { 59, "nonce[23]" },
            { 60, "ct_len[0]" },
            { 63, "ct_len[3]" },
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            unsigned char tampered[112];
            memcpy(tampered, base, blen);
            tampered[cases[i].off] ^= 0x01;
            int rc = kcap3_unpack(tampered, blen, KCAP3_FIXTURE_CODE, got);
            char msg[80];
            snprintf(msg, sizeof msg, "kcap3 tamper %s rejected", cases[i].name);
            CHECK(rc != 0, msg);
        }

        /* AC-01-A-02 / A-03: bad version, bad project_id (allowlist hit). */
        {
            unsigned char tampered[112];
            uint8_t bad_versions[] = { 0x00, 0x02, 0xFF };
            for (size_t i = 0; i < sizeof bad_versions; i++) {
                memcpy(tampered, base, blen);
                tampered[4] = bad_versions[i];
                CHECK(kcap3_unpack(tampered, blen, KCAP3_FIXTURE_CODE, got) != 0,
                      "kcap3 rejects bad version");
            }
            uint8_t bad_pids[] = { 0x00, 0xFF };
            for (size_t i = 0; i < sizeof bad_pids; i++) {
                memcpy(tampered, base, blen);
                tampered[5] = bad_pids[i];
                CHECK(kcap3_unpack(tampered, blen, KCAP3_FIXTURE_CODE, got) != 0,
                      "kcap3 rejects bad project_id");
            }
        }

        /* AC-01-A-04: any non-zero flags rejected. */
        {
            uint16_t bad_flags[] = { 0x0001, 0x0100, 0xFFFF };
            for (size_t i = 0; i < sizeof bad_flags / sizeof bad_flags[0]; i++) {
                unsigned char tampered[112];
                memcpy(tampered, base, blen);
                uint16_t v = kcap_put_le16(bad_flags[i]);
                memcpy(tampered + 6, &v, 2);
                CHECK(kcap3_unpack(tampered, blen, KCAP3_FIXTURE_CODE, got) != 0,
                      "kcap3 rejects non-zero flags");
            }
        }

        /* AC-01-C-04: truncated capsule (last byte missing). */
        CHECK(kcap3_unpack(base, blen - 1, KCAP3_FIXTURE_CODE, got) != 0,
              "kcap3 rejects truncated capsule");
        /* AC-01-C-04 (b): header itself truncated (< 64 bytes). */
        CHECK(kcap3_unpack(base, 63, KCAP3_FIXTURE_CODE, got) != 0,
              "kcap3 rejects sub-64-byte buffer");

        /* AC-01-C-05: oversized capsule (extra trailing bytes — size mismatch). */
        {
            unsigned char extra[120];
            memcpy(extra, base, blen);
            memset(extra + blen, 0, sizeof extra - blen);
            CHECK(kcap3_unpack(extra, sizeof extra, KCAP3_FIXTURE_CODE, got) != 0,
                  "kcap3 rejects oversized buffer");
        }

        /* Oversized ct_len that doesn't match file size (claim ct_len=200 in
           a 112-byte buffer). Receiver checks sizeof(hdr)+ct_len == blen. */
        {
            unsigned char tampered[112];
            memcpy(tampered, base, blen);
            uint32_t v = kcap_put_le32(200);
            memcpy(tampered + 60, &v, 4);
            CHECK(kcap3_unpack(tampered, blen, KCAP3_FIXTURE_CODE, got) != 0,
                  "kcap3 rejects ct_len/size mismatch");
        }
    }

    /* ===== 3. D-15 param policy enforcement =====
       Out-of-policy params MUST be rejected BEFORE Argon2id runs. We measure
       wall-clock time on the rejection: a real Argon2id call at default
       params takes ~50-100ms on this host; if the rejection is < 10ms we
       can be confident the policy gate fired before crypto_pwhash.

       Note: timing-based proof of "did not run Argon2id" is best-effort,
       but it's the same bar the existing test uses for argon2id timing
       sanity (B-06). Tolerance kept generous to avoid flakes on slow CI. */
    {
        unsigned char buf[112];
        size_t blen = 0;
        unsigned char got[32];

        /* B-07 floor: time_cost = 1, below KCAP3_MIN_TIME_COST. */
        CHECK(kcap3_pack_custom_params(KCAP3_FIXTURE_CODE, ref_priv,
                                       1, KCAP3_DEFAULT_MEM_COST,
                                       KCAP3_DEFAULT_PARALLELISM,
                                       buf, sizeof buf, &blen) == 0,
              "build out-of-policy capsule (time_cost=1)");
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = kcap3_unpack(buf, blen, KCAP3_FIXTURE_CODE, got);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        CHECK(rc != 0, "kcap3 rejects time_cost=1 (below floor)");
        double rej_ms = ms_since(t0, t1);
        fprintf(stderr, "info: param-floor rejection took %.3f ms\n", rej_ms);
        CHECK(rej_ms < 10.0,
              "kcap3 floor-rejection runs BEFORE Argon2id (< 10ms)");

        /* B-07 floor: mem_cost below KCAP3_MIN_MEM_COST. */
        CHECK(kcap3_pack_custom_params(KCAP3_FIXTURE_CODE, ref_priv,
                                       KCAP3_DEFAULT_TIME_COST, 1024,
                                       KCAP3_DEFAULT_PARALLELISM,
                                       buf, sizeof buf, &blen) == 0,
              "build out-of-policy capsule (mem_cost=1024)");
        CHECK(kcap3_unpack(buf, blen, KCAP3_FIXTURE_CODE, got) != 0,
              "kcap3 rejects mem_cost below floor");

        /* B-07 floor: parallelism = 0. */
        CHECK(kcap3_pack_custom_params(KCAP3_FIXTURE_CODE, ref_priv,
                                       KCAP3_DEFAULT_TIME_COST,
                                       KCAP3_DEFAULT_MEM_COST, 0,
                                       buf, sizeof buf, &blen) == 0,
              "build out-of-policy capsule (parallelism=0)");
        CHECK(kcap3_unpack(buf, blen, KCAP3_FIXTURE_CODE, got) != 0,
              "kcap3 rejects parallelism=0");

        /* B-08 ceiling: mem_cost > KCAP3_MAX_MEM_COST (8 GiB in KB). */
        CHECK(kcap3_pack_custom_params(KCAP3_FIXTURE_CODE, ref_priv,
                                       KCAP3_DEFAULT_TIME_COST, 8388608,
                                       KCAP3_DEFAULT_PARALLELISM,
                                       buf, sizeof buf, &blen) == 0,
              "build out-of-policy capsule (mem_cost=8GiB)");
        clock_gettime(CLOCK_MONOTONIC, &t0);
        rc = kcap3_unpack(buf, blen, KCAP3_FIXTURE_CODE, got);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        CHECK(rc != 0, "kcap3 rejects mem_cost above ceiling");
        rej_ms = ms_since(t0, t1);
        fprintf(stderr, "info: ceiling rejection took %.3f ms\n", rej_ms);
        CHECK(rej_ms < 10.0,
              "kcap3 ceiling-rejection runs BEFORE Argon2id (< 10ms)");

        /* B-08 ceiling: time_cost = 11 (above 10). */
        CHECK(kcap3_pack_custom_params(KCAP3_FIXTURE_CODE, ref_priv,
                                       11, KCAP3_DEFAULT_MEM_COST,
                                       KCAP3_DEFAULT_PARALLELISM,
                                       buf, sizeof buf, &blen) == 0,
              "build out-of-policy capsule (time_cost=11)");
        CHECK(kcap3_unpack(buf, blen, KCAP3_FIXTURE_CODE, got) != 0,
              "kcap3 rejects time_cost above ceiling");

        /* B-08 ceiling: parallelism = 17. */
        CHECK(kcap3_pack_custom_params(KCAP3_FIXTURE_CODE, ref_priv,
                                       KCAP3_DEFAULT_TIME_COST,
                                       KCAP3_DEFAULT_MEM_COST, 17,
                                       buf, sizeof buf, &blen) == 0,
              "build out-of-policy capsule (parallelism=17)");
        CHECK(kcap3_unpack(buf, blen, KCAP3_FIXTURE_CODE, got) != 0,
              "kcap3 rejects parallelism above ceiling");
    }

    /* ===== 4. KCAP3 fixture (testdata/kcap3.bin) =====
       Generate the deterministic fixture if missing (pinned salt+nonce),
       then verify it loads with the production kcap3_unpack. */
    {
        unsigned char salt[16], nonce[24];
        for (int i = 0; i < 16; i++) salt[i]  = (unsigned char)i;          /* 0x00..0x0F */
        for (int i = 0; i < 24; i++) nonce[i] = (unsigned char)(0x20 + i); /* 0x20..0x37 */

        if (!file_exists(KCAP3_FIXTURE_PATH)) {
            fprintf(stderr, "info: generating %s (pinned salt/nonce)\n", KCAP3_FIXTURE_PATH);
            unsigned char buf[112];
            size_t blen = 0;
            CHECK(kcap3_pack_pinned(KCAP3_FIXTURE_CODE, ref_priv, salt, nonce,
                                    buf, sizeof buf, &blen) == 0,
                  "kcap3 fixture pack");
            CHECK(blen == 112, "kcap3 fixture is 112 bytes");
            CHECK(write_file(KCAP3_FIXTURE_PATH, buf, blen) == 0,
                  "kcap3 fixture written");
        }

        unsigned char *fix = NULL; size_t fix_len = 0;
        CHECK(read_file(KCAP3_FIXTURE_PATH, &fix, &fix_len) == 0,
              "kcap3 fixture loaded");
        CHECK(fix_len == 112, "kcap3 fixture is exactly 112 bytes");
        CHECK(memcmp(fix, KCAP_FAMILY_MAGIC, 4) == 0, "kcap3 fixture magic == 'KCAP'");
        CHECK(fix[4] == KCAP_FAMILY_VERSION, "kcap3 fixture version == 0x01");
        CHECK(fix[5] == KCAP_PROJECT_EPHRUN, "kcap3 fixture project_id == 0x01");
        /* Pinned salt + nonce check (cross-platform fixture stability). */
        CHECK(memcmp(fix + 8, salt, 16) == 0, "kcap3 fixture salt pinned");
        CHECK(memcmp(fix + 36, nonce, 24) == 0, "kcap3 fixture nonce pinned");

        unsigned char fix_priv[32];
        CHECK(kcap3_unpack(fix, fix_len, KCAP3_FIXTURE_CODE, fix_priv) == 0,
              "kcap3 fixture decrypts");
        CHECK(memcmp(fix_priv, ref_priv, 32) == 0,
              "kcap3 fixture priv == bytes(0..31)");
        free(fix);
    }

    /* ===== 5. KCAP1 backward-read fixture ===== */
    {
        unsigned char *fix = NULL; size_t fix_len = 0;
        CHECK(read_file(KCAP1_FIXTURE_PATH, &fix, &fix_len) == 0,
              "kcap1 fixture loaded");
        CHECK(memcmp(fix, "KCAP1\0", 7) == 0, "kcap1 magic on fixture");
        unsigned char fix_priv[32];
        CHECK(decrypt_kcap_legacy_buf(KCAP1_FIXTURE_CODE, fix, fix_len, fix_priv) == 0,
              "kcap1 fixture decrypts with legacy KDF");
        for (int i = 0; i < 32; i++) {
            if (fix_priv[i] != (unsigned char)i) {
                fprintf(stderr, "FAIL: kcap1 fixture priv mismatch at %d\n", i);
                free(fix);
                return 1;
            }
        }
        fprintf(stderr, "ok:   kcap1 fixture priv bytes match\n");
        free(fix);
    }

    /* ===== 6. KCAP2 backward-read fixture =====
       Generate deterministically if missing. Pinned salt + nonce so the fixture
       on disk is reproducible regardless of host. */
    {
        unsigned char salt[16], nonce[24];
        /* Distinct from kcap3 fixture salts/nonces to avoid confusion. */
        for (int i = 0; i < 16; i++) salt[i]  = (unsigned char)(0x40 + i);
        for (int i = 0; i < 24; i++) nonce[i] = (unsigned char)(0x60 + i);

        if (!file_exists(KCAP2_FIXTURE_PATH)) {
            fprintf(stderr, "info: generating %s (pinned salt/nonce)\n", KCAP2_FIXTURE_PATH);
            unsigned char buf[200];
            size_t blen = 0;
            CHECK(kcap2_pack_pinned(KCAP2_FIXTURE_CODE, ref_priv, salt, nonce,
                                    buf, sizeof buf, &blen) == 0,
                  "kcap2 fixture pack");
            CHECK(write_file(KCAP2_FIXTURE_PATH, buf, blen) == 0,
                  "kcap2 fixture written");
        }

        unsigned char *fix = NULL; size_t fix_len = 0;
        CHECK(read_file(KCAP2_FIXTURE_PATH, &fix, &fix_len) == 0,
              "kcap2 fixture loaded");
        CHECK(memcmp(fix, "KCAP2\0", 7) == 0, "kcap2 magic on fixture");
        unsigned char fix_priv[32];
        CHECK(decrypt_kcap_legacy_buf(KCAP2_FIXTURE_CODE, fix, fix_len, fix_priv) == 0,
              "kcap2 fixture decrypts via legacy KCAP2 path");
        CHECK(memcmp(fix_priv, ref_priv, 32) == 0,
              "kcap2 fixture priv == bytes(0..31)");
        free(fix);
    }

    /* ===== 7. Argon2id timing sanity (AC-01-B-06) ===== */
    {
        unsigned char buf[112];
        size_t blen = 0;
        CHECK(kcap3_pack(KCAP3_FIXTURE_CODE, ref_priv, buf, sizeof buf, &blen) == 0,
              "kcap3 pack for timing");
        unsigned char got[32];
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        CHECK(kcap3_unpack(buf, blen, KCAP3_FIXTURE_CODE, got) == 0,
              "kcap3 unpack for timing");
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double elapsed = ms_since(t0, t1);
        fprintf(stderr, "info: kcap3 unwrap took %.1f ms\n", elapsed);
        if (elapsed < 50.0) {
            fprintf(stderr, "FAIL: kcap3 unwrap suspiciously fast (<50ms) — short-circuit?\n");
            return 1;
        }
        fprintf(stderr, "ok:   kcap3 unwrap >= 50ms\n");
    }

    /* ===== 8. Bad magic / not a KCAP3 capsule rejection ===== */
    {
        unsigned char buf[112] = {0};
        memcpy(buf, "XXXX", 4);
        buf[4] = 0x01;
        unsigned char got[32];
        CHECK(kcap3_unpack(buf, sizeof buf, KCAP3_FIXTURE_CODE, got) != 0,
              "kcap3 rejects buffer with non-KCAP magic");
    }

    fprintf(stderr, "ALL TESTS PASSED\n");
    return 0;
}
