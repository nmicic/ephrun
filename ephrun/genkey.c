/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 */
#include <sodium.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) return 1;
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);

    FILE *f = fopen("pub.bin","wb");
    if (!f) { perror("pub.bin"); return 1; }
    fwrite(pk,1,sizeof pk,f);  fclose(f);

    f = fopen("priv.bin","wb");
    if (!f) { perror("priv.bin"); return 1; }
    fwrite(sk,1,sizeof sk,f);  fclose(f);

    char hexpk[crypto_box_PUBLICKEYBYTES*2+1];
    sodium_bin2hex(hexpk, sizeof hexpk, pk, sizeof pk);
    printf("pub(hex): %s\n", hexpk);
    printf("Written: pub.bin, priv.bin\n");
    sodium_memzero(sk, sizeof sk);
    return 0;
}

