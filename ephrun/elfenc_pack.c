/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 */
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200112L
#include <sodium.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* portable little-endian store (no-op on x86; byte-swap on big-endian) */
static inline uint64_t put_le64(uint64_t v){
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(v);
#else
    return v;
#endif
}

#pragma pack(push,1)
struct elfenc_hdr {
    char magic[8];      // "ELFENC1\0"
    uint64_t clen;      // ciphertext length
};
#pragma pack(pop)

static int read_all(const char *p, unsigned char **buf, size_t *len){
    *buf = NULL;
    *len = 0;

    FILE *f = fopen(p, "rb");
    if (!f) return -1;
    if (fseeko(f, 0, SEEK_END) != 0) { fclose(f); return -2; }
    off_t L = ftello(f);
    if (L < 0) { fclose(f); return -2; }
    if (fseeko(f, 0, SEEK_SET) != 0) { fclose(f); return -2; }
    if (L == 0 || (uintmax_t)L > (uintmax_t)SIZE_MAX) {
        fclose(f);
        return -3;
    }

    size_t n = (size_t)L;
    unsigned char *tmp = (unsigned char *)malloc(n);
    if (!tmp) { fclose(f); return -4; }
    if (fread(tmp, 1, n, f) != n) {
        free(tmp);
        fclose(f);
        return -5;
    }
    if (fclose(f) != 0) {
        free(tmp);
        return -6;
    }

    *buf = tmp;
    *len = n;
    return 0;
}

static int read_pubkey(const char *p, unsigned char pk[crypto_box_PUBLICKEYBYTES]) {
    FILE *f = fopen(p, "rb");
    if (!f) return -1;
    size_t n = fread(pk, 1, crypto_box_PUBLICKEYBYTES, f);
    int extra = fgetc(f);
    int err = ferror(f);
    fclose(f);
    if (n != crypto_box_PUBLICKEYBYTES || err || extra != EOF) return -1;
    return 0;
}

static int write_all_fd(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int open_temp_output(const char *out_path, char **tmp_path_out) {
    size_t out_len = strlen(out_path);
    char *tmp = (char *)malloc(out_len + 64);
    if (!tmp) return -1;

    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    for (int i = 0; i < 100; i++) {
        snprintf(tmp, out_len + 64, "%s.tmp.%ld.%d", out_path, (long)getpid(), i);
        int fd = open(tmp, flags, 0600);
        if (fd >= 0) {
            *tmp_path_out = tmp;
            return fd;
        }
        if (errno != EEXIST) break;
    }

    free(tmp);
    return -1;
}

static int write_output_atomic_no_replace(const char *out_path,
                                          const struct elfenc_hdr *hdr,
                                          const unsigned char *cipher,
                                          size_t clen) {
    char *tmp_path = NULL;
    int fd = open_temp_output(out_path, &tmp_path);
    if (fd < 0) return -1;

    int ok = 0;
    if (fchmod(fd, 0644) == 0 &&
        write_all_fd(fd, hdr, sizeof *hdr) == 0 &&
        write_all_fd(fd, cipher, clen) == 0 &&
        fsync(fd) == 0) {
        int close_rc = close(fd);
        fd = -1;
        if (close_rc == 0 && link(tmp_path, out_path) == 0) {
            ok = 1;
        }
    }

    int saved = errno ? errno : EIO;
    if (fd >= 0) close(fd);
    unlink(tmp_path);
    free(tmp_path);
    if (!ok) {
        errno = saved;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv){
    if (argc < 4) { fprintf(stderr,"usage: %s <pub.bin> <in.elf> <out.elfenc>\n",argv[0]); return 2; }
    if (sodium_init() < 0) return 1;

    // load pubkey
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    if (read_pubkey(argv[1], pk) != 0) {
        fprintf(stderr, "bad pub.bin\n");
        return 1;
    }

    // read input ELF
    unsigned char *plain=NULL; size_t plen=0;
    int rr = read_all(argv[2], &plain, &plen);
    if (rr) {
        fprintf(stderr,"read %s failed (rc=%d)\n", argv[2], rr);
        return 1;
    }
    if (plen > SIZE_MAX - crypto_box_SEALBYTES) {
        fprintf(stderr,"input too large\n");
        sodium_memzero(plain, plen);
        free(plain);
        return 1;
    }

    // seal (X25519 + XSalsa20-Poly1305)
    size_t clen = plen + crypto_box_SEALBYTES;
    unsigned char *cipher = malloc(clen);
    if (!cipher) {
        sodium_memzero(plain, plen);
        free(plain);
        return 1;
    }
    if (crypto_box_seal(cipher, plain, plen, pk) != 0) {
        fprintf(stderr,"seal failed\n");
        sodium_memzero(plain, plen); free(plain);
        sodium_memzero(cipher, clen); free(cipher);
        return 1;
    }

    // write output
    struct elfenc_hdr H; memcpy(H.magic,"ELFENC1",7); H.magic[7]='\0'; H.clen = put_le64((uint64_t)clen);
    if (write_output_atomic_no_replace(argv[3], &H, cipher, clen) != 0) {
        perror("write output");
        sodium_memzero(plain, plen); free(plain);
        sodium_memzero(cipher, clen); free(cipher);
        return 1;
    }
    sodium_memzero(plain, plen); free(plain);
    sodium_memzero(cipher, clen); free(cipher);
    return 0;
}
