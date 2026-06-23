/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 */
#include <sodium.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_all_fd(int fd, const unsigned char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        buf += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int write_new_file(const char *path, const unsigned char *buf, size_t len, mode_t mode) {
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(path, flags, mode);
    if (fd < 0) return -1;

    if (fchmod(fd, mode) != 0 || write_all_fd(fd, buf, len) != 0) {
        int saved = errno ? errno : EIO;
        close(fd);
        unlink(path);
        errno = saved;
        return -1;
    }
    if (close(fd) != 0) {
        int saved = errno;
        unlink(path);
        errno = saved;
        return -1;
    }
    return 0;
}

int main(void) {
    if (sodium_init() < 0) return 1;
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);

    if (write_new_file("priv.bin", sk, sizeof sk, 0600) != 0) {
        perror("priv.bin");
        sodium_memzero(sk, sizeof sk);
        return 1;
    }
    if (write_new_file("pub.bin", pk, sizeof pk, 0644) != 0) {
        perror("pub.bin");
        unlink("priv.bin");
        sodium_memzero(sk, sizeof sk);
        return 1;
    }

    char hexpk[crypto_box_PUBLICKEYBYTES*2+1];
    sodium_bin2hex(hexpk, sizeof hexpk, pk, sizeof pk);
    printf("pub(hex): %s\n", hexpk);
    printf("Written: pub.bin, priv.bin (priv.bin mode 0600)\n");
    sodium_memzero(sk, sizeof sk);
    return 0;
}
