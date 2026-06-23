/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 *
 * kcap.h — Shared KCAP capsule definitions
 *
 * Three capsule formats live here:
 *   - KCAP3 (current, primary): family-magic "KCAP" + version 0x01 + project_id.
 *                               64-byte AAD-bound header, params-in-header
 *                               Argon2id, XChaCha20-Poly1305-IETF AEAD.
 *                               Defined by D-13. See kcap3_pack/kcap3_unpack.
 *   - KCAP2 (legacy read-only): 7-byte magic "KCAP2\0", Argon2id KDF.
 *                               Still readable via kcap_derive_k_v2.
 *   - KCAP1 (legacy read-only): 7-byte magic "KCAP1\0", SHA256 KDF.
 *                               Still readable via kcap_derive_k. Do NOT extend.
 *
 * Used by: elfdec-run.c, kcap_pack.c, kcap_unpack.c, libexec_key.h,
 *          kcap_kdf_test.c.
 */

#ifndef KCAP_H
#define KCAP_H

#include <errno.h>
#include <sodium.h>
#include <stdint.h>
#include <string.h>

/* ---------- Portable endian helpers ---------- */

static inline uint64_t kcap_get_le64(uint64_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(v);
#else
    return v;
#endif
}

static inline uint32_t kcap_get_le32(uint32_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap32(v);
#else
    return v;
#endif
}

static inline uint16_t kcap_get_le16(uint16_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap16(v);
#else
    return v;
#endif
}

static inline uint64_t kcap_put_le64(uint64_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(v);
#else
    return v;
#endif
}

static inline uint32_t kcap_put_le32(uint32_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap32(v);
#else
    return v;
#endif
}

static inline uint16_t kcap_put_le16(uint16_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap16(v);
#else
    return v;
#endif
}

/* ---------- KCAP1/KCAP2 legacy binary header ----------
   Same shape for KCAP1 and KCAP2 — only the magic and KDF differ.
   Layout: magic[7] + _pad, u64 t0, u32 ttl,
           salt[16], nonce[24], u32 ct_len, then ct[ct_len]
*/
#pragma pack(push,1)
struct kcap_bin_hdr {
    char magic[7];      /* "KCAP1\0" (legacy) or "KCAP2\0" (legacy) */
    uint8_t _pad;
    uint64_t t0;
    uint32_t ttl;
    unsigned char salt[16];
    unsigned char nonce[24];
    uint32_t ct_len;
};
#pragma pack(pop)

/* ---------- KCAP3 (current primary format) ----------
   Wire format per DECISIONS.md D-13:

     offset  size  field
        0     4    magic[4]      "KCAP" (family preamble)
        4     1    version       0x01
        5     1    project_id    0x01 (ephrun)
        6     2    flags         uint16 LE; v1 readers reject any non-zero value
        8    16    salt
       24     4    time_cost     uint32 LE
       28     4    mem_cost      uint32 LE in KB
       32     4    parallelism   uint32 LE
       36    24    nonce
       60     4    ct_len        uint32 LE
       64    ct_len  ct          XChaCha20-Poly1305-IETF, AAD = bytes [0..63]

   Plaintext = priv[32]. K = Argon2id(passphrase, salt; T,M,P from header).

   Receiver enforces D-15 param floor + ceiling on T/M/P BEFORE invoking
   crypto_pwhash. AAD is exactly the first 64 bytes of the buffer (the full
   fixed header inclusive of nonce + ct_len).
*/

#define KCAP_FAMILY_MAGIC      "KCAP"   /* 4 bytes, no NUL */
#define KCAP_FAMILY_VERSION    0x01
#define KCAP_PROJECT_EPHRUN  0x01

/* Default Argon2id parameters for fresh KCAP3 capsules (D-13). */
#define KCAP3_DEFAULT_TIME_COST    3u
#define KCAP3_DEFAULT_MEM_COST     65536u   /* in KB; = 64 MiB */
#define KCAP3_DEFAULT_PARALLELISM  1u

/* D-15 receiver-side param policy floor + ceiling. */
#define KCAP3_MIN_TIME_COST        3u
#define KCAP3_MAX_TIME_COST        10u
#define KCAP3_MIN_MEM_COST         65536u    /* 64 MiB in KB */
#define KCAP3_MAX_MEM_COST         4194304u  /* 4 GiB in KB */
#define KCAP3_MIN_PARALLELISM      1u
#define KCAP3_MAX_PARALLELISM      16u

#pragma pack(push,1)
struct kcap3_hdr {
    char magic[4];               /* "KCAP" */
    uint8_t version;             /* 0x01 */
    uint8_t project_id;          /* 0x01 (ephrun) */
    uint16_t flags;              /* uint16 LE; v1 = 0 */
    unsigned char salt[16];      /* random salt */
    uint32_t time_cost;          /* Argon2id T, uint32 LE */
    uint32_t mem_cost;           /* Argon2id M (KB), uint32 LE */
    uint32_t parallelism;        /* Argon2id P, uint32 LE */
    unsigned char nonce[24];     /* XChaCha20 nonce */
    uint32_t ct_len;             /* ciphertext length, uint32 LE */
};
#pragma pack(pop)

/* The wire format MUST be exactly 64 bytes. Any drift (compiler padding,
   typo) is a load-bearing bug that needs to fail the build, not the test. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct kcap3_hdr) == 64,
               "kcap3_hdr must be exactly 64 bytes (D-13 wire format)");
#else
typedef char kcap3_hdr_size_check[(sizeof(struct kcap3_hdr) == 64) ? 1 : -1];
#endif

/* ---------- KCAP3 receiver-side param policy check ----------
   Per D-15. Called BEFORE crypto_pwhash to defend against malicious
   packers and DoS. Returns 0 if all params are in policy, -1 otherwise.
   Caller is expected to map -1 to a clear error message and reject.
*/
static inline int kcap3_check_params(uint32_t t, uint32_t m, uint32_t p) {
    if (t < KCAP3_MIN_TIME_COST    || t > KCAP3_MAX_TIME_COST)    return -1;
    if (m < KCAP3_MIN_MEM_COST     || m > KCAP3_MAX_MEM_COST)     return -1;
    if (p < KCAP3_MIN_PARALLELISM  || p > KCAP3_MAX_PARALLELISM)  return -1;
    return 0;
}

/* ---------- KCAP3 writer ----------
   Generates fresh salt + nonce, builds 64-byte header, derives K via
   Argon2id, AEAD-encrypts priv[32] with AAD = first 64 bytes of out_buf.
   Total bytes written = 64 + 32 + 16 = 112.

   Returns 0 on success (out_len set to total bytes written),
           -1 on any failure (incl. Argon2id OOM, AEAD failure,
                              insufficient out_cap).
   K is sodium_memzero'd before return on every code path.
*/
static inline int kcap3_pack(const char *passphrase,
                             const unsigned char priv[32],
                             unsigned char *out_buf, size_t out_cap,
                             size_t *out_len) {
    if (!passphrase || !priv || !out_buf || !out_len) return -1;

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
    H.time_cost   = kcap_put_le32(KCAP3_DEFAULT_TIME_COST);
    H.mem_cost    = kcap_put_le32(KCAP3_DEFAULT_MEM_COST);
    H.parallelism = kcap_put_le32(KCAP3_DEFAULT_PARALLELISM);
    H.ct_len      = kcap_put_le32((uint32_t)ct_len);

    /* Place the header into out_buf first; AAD points into out_buf. */
    memcpy(out_buf, &H, sizeof H);

    unsigned char K[32];
    /* Argon2id memlimit takes BYTES, not KB — convert from header KB. */
    size_t memlimit_bytes = (size_t)KCAP3_DEFAULT_MEM_COST * 1024u;
    if (crypto_pwhash(K, 32,
                      passphrase, strlen(passphrase),
                      H.salt,
                      KCAP3_DEFAULT_TIME_COST,
                      memlimit_bytes,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(K, sizeof K);
        sodium_memzero(out_buf, sizeof H);
        return -1;
    }

    unsigned long long olen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out_buf + sizeof H, &olen,
            priv, 32,
            out_buf, sizeof H,        /* AAD = first 64 bytes (full header) */
            NULL,
            H.nonce, K) != 0) {
        sodium_memzero(K, sizeof K);
        sodium_memzero(out_buf, total);
        return -1;
    }
    sodium_memzero(K, sizeof K);

    if ((size_t)olen != ct_len) {
        sodium_memzero(out_buf, total);
        return -1;
    }
    *out_len = total;
    return 0;
}

/* ---------- KCAP3 reader ----------
   Validates the 64-byte header strictly (allowlist on every byte that has
   semantics), enforces D-15 param policy BEFORE Argon2id, then AEAD-decrypts
   with AAD = first 64 bytes of buf.

   priv_out[32] is written only on success. K is sodium_memzero'd before return.

   Returns 0 on success, -1 on any failure with errno set:
     - EINVAL: bad magic / version / project_id / flags / ct_len / blen,
               or D-15 param policy violation.
     - ENOMEM: Argon2id (crypto_pwhash) allocation failure — typically the
               cgroup / RLIMIT_AS hit before Argon2id could allocate
               mem_cost KiB. Distinguished from EACCES so callers (and
               operators) can tell "you ran out of memory" from "your
               passphrase is wrong".
     - EACCES: AEAD decrypt failure — wrong passphrase or tampered capsule.
*/
static inline int kcap3_unpack(const unsigned char *buf, size_t blen,
                               const char *passphrase,
                               unsigned char priv_out[32]) {
    if (!buf || !passphrase || !priv_out) { errno = EINVAL; return -1; }
    if (blen < sizeof(struct kcap3_hdr))   { errno = EINVAL; return -1; }

    struct kcap3_hdr H;
    memcpy(&H, buf, sizeof H);

    /* Allowlist validation — every header field with assigned semantics. */
    if (memcmp(H.magic, KCAP_FAMILY_MAGIC, 4) != 0)   { errno = EINVAL; return -1; }
    if (H.version    != KCAP_FAMILY_VERSION)          { errno = EINVAL; return -1; }
    if (H.project_id != KCAP_PROJECT_EPHRUN)        { errno = EINVAL; return -1; }
    if (kcap_get_le16(H.flags) != 0)                  { errno = EINVAL; return -1; }

    uint32_t t = kcap_get_le32(H.time_cost);
    uint32_t m = kcap_get_le32(H.mem_cost);
    uint32_t p = kcap_get_le32(H.parallelism);
    /* D-15: enforce param policy BEFORE invoking Argon2id. */
    if (kcap3_check_params(t, m, p) != 0)             { errno = EINVAL; return -1; }

    uint32_t ct_len = kcap_get_le32(H.ct_len);
    /* Pre-bound ct_len against blen to defeat any 32-bit size_t addition wrap
       on a malicious huge ct_len. blen is already known to be at least sizeof H. */
    if ((size_t)ct_len > blen - sizeof H)             { errno = EINVAL; return -1; }
    if (sizeof H + (size_t)ct_len != blen)            { errno = EINVAL; return -1; }
    /* For raw priv[32] plaintext, ciphertext is exactly 32 + 16 = 48. */
    if (ct_len != 32u + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        errno = EINVAL; return -1;
    }

    unsigned char K[32];
    size_t memlimit_bytes = (size_t)m * 1024u;
    if (crypto_pwhash(K, 32,
                      passphrase, strlen(passphrase),
                      H.salt,
                      t,
                      memlimit_bytes,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(K, sizeof K);
        /* libsodium does not document errno on crypto_pwhash failure; the
         * realistic runtime cause is allocation failure (memlimit > available
         * memory under cgroup/RLIMIT_AS), so set ENOMEM explicitly. AC-03-09
         * relies on this distinguishability. */
        errno = ENOMEM;
        return -1;
    }

    unsigned char plain[32];
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain, NULL, NULL,
            buf + sizeof H, ct_len,
            buf, sizeof H,        /* AAD = first 64 bytes (full header) */
            H.nonce, K) != 0) {
        sodium_memzero(K, sizeof K);
        sodium_memzero(plain, sizeof plain);
        errno = EACCES;
        return -1;
    }
    sodium_memzero(K, sizeof K);
    memcpy(priv_out, plain, 32);
    sodium_memzero(plain, sizeof plain);
    return 0;
}

/* ---------- KCAP2 KDF: Argon2id ----------
   K = Argon2id(code, salt) — opslimit=3, memlimit=64 MiB.
   Read-only legacy path; new capsules use kcap3_pack.
   Returns 0 on success, -1 on failure.
*/
static inline int kcap_derive_k_v2(const char *code, const unsigned char salt[16],
                                    unsigned char K[32]) {
    if (crypto_pwhash(K, 32,
                      code, strlen(code),
                      salt,
                      3,                /* opslimit (T=3)        */
                      67108864,         /* memlimit (M=64 MiB)   */
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return -1;
    }
    return 0;
}

/* ---------- KCAP1 legacy KDF (read-only) ----------
   K = SHA256("elfdec-kcap" || salt || SHA256(code))
   DO NOT use for new capsules — single-pass SHA256 is brute-forceable on GPUs.
   Kept solely so already-deployed KCAP1 capsules remain decryptable.
*/
static inline void kcap_derive_k(const char *code, const unsigned char salt[16],
                                  unsigned char K[32]) {
    unsigned char s[32];
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, (const unsigned char *)code, strlen(code));
    crypto_hash_sha256_final(&st, s);

    crypto_hash_sha256_init(&st);
    const char *tag = "elfdec-kcap";
    crypto_hash_sha256_update(&st, (const unsigned char *)tag, strlen(tag));
    crypto_hash_sha256_update(&st, salt, 16);
    crypto_hash_sha256_update(&st, s, 32);
    crypto_hash_sha256_final(&st, K);
    sodium_memzero(s, sizeof s);
}

#endif /* KCAP_H */
