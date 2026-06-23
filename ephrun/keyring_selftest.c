/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 *
sudo apt-get install -y keyutils libkeyutils-dev libsodium-dev build-essential

# compile
gcc -O2 -Wall keyring_selftest.c -lkeyutils -lsodium -o keyring_selftest

# run
./keyring_selftest

# keep the keys around for manual inspection
KEEP_KEYS=1 ./keyring_selftest
keyctl describe <ID_SHOWN>
keyctl rdescribe <ID_SHOWN>
keyctl print     <ID_SHOWN> | hexdump -Cv     # (or: keyctl read ... | wc -c)

*/
// gcc -O2 -Wall keyring_selftest.c -lkeyutils -lsodium -o keyring_selftest
#define _GNU_SOURCE
#include <keyutils.h>
#include <sodium.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x, msg) do { if ((x) < 0) { perror(msg); exit(1); } } while (0)
#define DIE(msg) do { perror(msg); exit(1); } while (0)

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) DIE("malloc");
    return p;
}

static void hexdump(const unsigned char *buf, size_t n) {
    for (size_t i=0;i<n;i++) printf("%02x", buf[i]);
}

int main(void) {
    // --- Init ---
    if (sodium_init() < 0) DIE("sodium_init");
    key_serial_t s = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 1);
    CHECK(s, "get @s");

    // --- Make unique descriptions ---
    unsigned char rsuf[6]; randombytes_buf(rsuf, sizeof rsuf);
    char suf[16]; sodium_bin2hex(suf, sizeof suf, rsuf, sizeof rsuf);
    char desc_key[128], desc_ct[128];
    snprintf(desc_key, sizeof desc_key, "elfdec:selftest:key:%ld:%d:%s",
             (long)time(NULL), (int)getpid(), suf);
    snprintf(desc_ct,  sizeof desc_ct,  "elfdec:selftest:ct:%ld:%d:%s",
             (long)time(NULL), (int)getpid(), suf);

    // --- Generate 32B secret and 1024B plaintext ---
    unsigned char secret[32]; randombytes_buf(secret, sizeof secret);
    size_t pt_len = 1024;
    unsigned char *pt = xmalloc(pt_len);
    randombytes_buf(pt, pt_len);

    // --- Add key to @s, set owner read, link to @u (best-effort) ---
    key_serial_t key_id = add_key("user", desc_key, secret, sizeof secret, s);
    CHECK(key_id, "add_key(secret->@s)");

    unsigned int perm = 0x3f030000U; // possessor: all; owner: view+read; grp/other: none
    CHECK(keyctl_setperm(key_id, perm), "setperm(secret)");

    // optional anchoring in @u for persistence
    keyctl_link(key_id, KEY_SPEC_USER_KEYRING); // ignore errors here

    // --- Prove we can read the key back by ID ---
    void *secret_rd = NULL;
    long slen = keyctl_read_alloc(key_id, &secret_rd);
    CHECK(slen, "read(secret by id)");
    if ((size_t)slen != sizeof secret || memcmp(secret, secret_rd, sizeof secret) != 0) {
        fprintf(stderr, "Mismatch reading back secret\n");
        return 1;
    }
    free(secret_rd);

    // --- Encrypt plaintext using key fetched from keyring ---
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    size_t ct_len = crypto_secretbox_MACBYTES + pt_len;
    unsigned char *ct = xmalloc(ct_len);

    if (crypto_secretbox_easy(ct, pt, pt_len, nonce, secret) != 0) {
        fprintf(stderr, "secretbox failed\n"); return 1;
    }

    // --- Store (nonce||ciphertext) as another key ---
    size_t blob_len = sizeof nonce + ct_len;
    unsigned char *blob = xmalloc(blob_len);
    memcpy(blob, nonce, sizeof nonce);
    memcpy(blob + sizeof nonce, ct, ct_len);

    key_serial_t ct_id = add_key("user", desc_ct, blob, blob_len, s);
    CHECK(ct_id, "add_key(cipher->@s)");
    CHECK(keyctl_setperm(ct_id, perm), "setperm(cipher)");
    keyctl_link(ct_id, KEY_SPEC_USER_KEYRING); // ignore errors

    // --- Read & decrypt back (same session) ---
    void *blob_rd = NULL;
    long bl = keyctl_read_alloc(ct_id, &blob_rd);
    CHECK(bl, "read(cipher by id)");
    if ((size_t)bl != blob_len) { fprintf(stderr, "cipher blob size mismatch\n"); return 1; }

    unsigned char *nonce2 = (unsigned char *)blob_rd;
    unsigned char *ct2    = (unsigned char *)blob_rd + sizeof nonce;
    unsigned char *pt2    = xmalloc(pt_len);

    if (crypto_secretbox_open_easy(pt2, ct2, ct_len, nonce2, secret) != 0) {
        fprintf(stderr, "secretbox_open failed (same session)\n"); return 1;
    }
    if (memcmp(pt, pt2, pt_len) != 0) {
        fprintf(stderr, "plaintext mismatch (same session)\n"); return 1;
    }
    free(pt2);
    free(blob_rd);

    // --- Hash for human confirmation ---
    unsigned char h1[crypto_generichash_BYTES], h2[crypto_generichash_BYTES];
    crypto_generichash(h1, sizeof h1, pt, pt_len, NULL, 0);
    crypto_generichash(h2, sizeof h2, ct, ct_len, NULL, 0);

    printf("OK same-session:\n");
    printf("  key id: %d  desc: %s\n", key_id, desc_key);
    printf("  ct id : %d  desc: %s\n", ct_id,  desc_ct);
    printf("  pt hash: "); hexdump(h1, sizeof h1); printf("\n");
    printf("  ct hash: "); hexdump(h2, sizeof h2); printf("\n");

    // --- Drop possession: join a brand-new session keyring ---
    key_serial_t ns = keyctl_join_session_keyring("selftest_isolated");
    CHECK(ns, "join_session_keyring");

    // Expect search by description to fail now (not reachable from new @s)
    key_serial_t should_fail = keyctl_search(ns, "user", desc_key, 0);
    if (should_fail >= 0) {
        fprintf(stderr, "BUG: search unexpectedly succeeded in new session\n");
        return 1;
    }

    // But reading by **ID** should succeed (owner read is granted)
    void *secret_rd2 = NULL;
    slen = keyctl_read_alloc(key_id, &secret_rd2);
    CHECK(slen, "read(secret by id in new session)");
    if ((size_t)slen != sizeof secret) { fprintf(stderr, "size mismatch (secret)\n"); return 1; }

    // Decrypt again using the key we just read by ID (new session)
    unsigned char *pt3 = xmalloc(pt_len);
    if (crypto_secretbox_open_easy(pt3, ct, ct_len, nonce, secret_rd2) != 0) {
        fprintf(stderr, "secretbox_open failed (new session)\n"); return 1;
    }
    if (memcmp(pt, pt3, pt_len) != 0) {
        fprintf(stderr, "plaintext mismatch (new session)\n"); return 1;
    }
    free(secret_rd2);
    free(pt3);

    printf("OK new-session:\n");
    printf("  read-by-id works without possession (owner read)\n");

    // --- Cleanup (optional: skip if KEEP_KEYS=1) ---
    const char *keep = getenv("KEEP_KEYS");
    if (!keep || strcmp(keep, "1") != 0) {
        // best-effort: unlink from user keyring (works across sessions)
        keyctl_unlink(key_id, KEY_SPEC_USER_KEYRING);
        keyctl_unlink(ct_id,  KEY_SPEC_USER_KEYRING);
        // (the copies in the original @s will be gc'd when not referenced)
    } else {
        printf("KEEP_KEYS=1 set — not unlinking from @u\n");
    }

    free(pt);
    free(ct);
    free(blob);

    puts("SELFTEST PASS");
    return 0;
}
