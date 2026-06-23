/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 */
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200112L
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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
    FILE *f=fopen(p,"rb"); if(!f) return -1;
    fseeko(f,0,SEEK_END); off_t L=ftello(f); fseeko(f,0,SEEK_SET);
    *buf = malloc(L); if(!*buf){ fclose(f); return -2; }
    if (fread(*buf,1,L,f)!=(size_t)L){ fclose(f); free(*buf); return -3;}
    fclose(f); *len=L; return 0;
}

int main(int argc, char **argv){
    if (argc < 4) { fprintf(stderr,"usage: %s <pub.bin> <in.elf> <out.elfenc>\n",argv[0]); return 2; }
    if (sodium_init() < 0) return 1;

    // load pubkey
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    { FILE *f=fopen(argv[1],"rb"); if(!f){perror("pub.bin");return 1;}
      if (fread(pk,1,sizeof pk,f)!=sizeof pk){fprintf(stderr,"bad pub.bin\n"); return 1;}
      fclose(f);
    }

    // read input ELF
    unsigned char *plain=NULL; size_t plen=0;
    if (read_all(argv[2], &plain, &plen)) { fprintf(stderr,"read %s failed\n", argv[2]); return 1; }

    // seal (X25519 + XSalsa20-Poly1305)
    size_t clen = plen + crypto_box_SEALBYTES;
    unsigned char *cipher = malloc(clen);
    if (!cipher) return 1;
    if (crypto_box_seal(cipher, plain, plen, pk) != 0) { fprintf(stderr,"seal failed\n"); return 1; }

    // write output
    FILE *out = fopen(argv[3],"wb");
    if(!out){ perror("out"); return 1; }
    struct elfenc_hdr H; memcpy(H.magic,"ELFENC1",7); H.magic[7]='\0'; H.clen = put_le64((uint64_t)clen);
    if (fwrite(&H,1,sizeof H,out) != sizeof H ||
        fwrite(cipher,1,clen,out) != clen) {
        perror("write output"); fclose(out); return 1;
    }
    fclose(out);
    sodium_memzero(plain, plen); free(plain);
    sodium_memzero(cipher, clen); free(cipher);
    return 0;
}

