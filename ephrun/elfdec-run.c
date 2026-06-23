/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 */
// elfdec-run.c — Encrypted ELF runner with capsule/keyring/file fallback
// Priority:
// 1) ELFDEC_CODE  -> decrypt capsule (from keyring elfdec_caps:<label> or ELFDEC_KEYPATH/{capsule.bin|json})
// 2) ELFDEC_KEYID or ELFDEC_LABEL -> read 32B secret from keyring, derive pub
// 3) ELFDEC_KEYPATH -> read {priv.bin,pub.bin} in that dir
// 4) ~/.elfenc/{priv.bin,pub.bin}
//
// Build:  gcc -O2 -Wall -Wextra -D_GNU_SOURCE elfdec-run.c -lsodium -lkeyutils -o elfdec-run

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64

#include <sodium.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <keyutils.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002
#endif
/* MFD_EXEC: kernel value is 0x0010 (introduced in 6.3, May 2023). We do NOT
 * provide a local fallback — pre-6.3 kernels reject any unknown bit in the
 * memfd_create flags with EINVAL, so passing a fake value would brick
 * memfd_create on every older kernel. If the host's headers don't define
 * MFD_EXEC the call simply doesn't request it; if they do, memfd_create_compat
 * below retries without the bit on EINVAL so a userspace compiled against new
 * headers still runs on an older kernel. (D-20.) */
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

/* shared capsule definitions (endian helpers, kcap_bin_hdr, KDF) */
#include "kcap.h"

/* convenience aliases for existing code */
#define get_le64 kcap_get_le64
#define get_le32 kcap_get_le32

extern char **environ;

#pragma pack(push,1)
struct elfenc_hdr {
    char magic[8];      // "ELFENC1\0"
    uint64_t clen;      // ciphertext length
};
#pragma pack(pop)

/* kcap_bin_hdr is now in kcap.h */

/* ===== utils ===== */

static int xdie(const char *fmt, ...) {
    int saved_errno = errno;
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    if (saved_errno) fprintf(stderr, " (%s)", strerror(saved_errno));
    fputc('\n', stderr); return 1;
}

static int read_exact(int fd, void *buf, size_t n){
    size_t off=0; while(off<n){ ssize_t r=read(fd,(char*)buf+off,n-off); if(r<=0) return -1; off+=r; } return 0;
}

static int memfd_create_compat(const char *name, unsigned int flags){
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, name, flags);
#ifdef MFD_EXEC
    /* D-20: kernels < 6.3 reject MFD_EXEC with EINVAL. Retry without the bit
     * so a userspace built on a 6.3+ box (where headers define MFD_EXEC) still
     * works on a 5.15-era host. The resulting memfd may be subject to that
     * kernel's default exec policy; the /dev/shm ETXTBSY fallback handles the
     * remaining edge cases. */
    if (fd < 0 && errno == EINVAL && (flags & MFD_EXEC)) {
        fd = (int)syscall(SYS_memfd_create, name, flags & ~(unsigned)MFD_EXEC);
    }
#endif
    return fd;
#else
    (void)name; (void)flags;
    errno = ENOSYS; return -1;
#endif
}

static int execveat_compat(int dirfd, const char *pathname,
                           char *const argv[], char *const envp[], int flags) {
#ifdef SYS_execveat
    return (int)syscall(SYS_execveat, dirfd, pathname, argv, envp, flags);
#else
    (void)dirfd; (void)pathname; (void)argv; (void)envp; (void)flags;
    errno = ENOSYS; return -1;
#endif
}

/* Defense-in-depth (D-18): refuse to run if a ptrace tracer is attached.
 * Returns >0 (tracer pid) if a tracer is present, 0 if not, -1 on error.
 * /proc/self/status is read once at startup; no side effects, no
 * PTRACE_TRACEME (whose signal-delivery semantics survive fexecve). */
static pid_t get_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    pid_t tracer = 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer = (pid_t)strtol(line + 10, NULL, 10);
            break;
        }
    }
    fclose(f);
    return tracer;
}

/* D-17: env vars that elfdec-run consumes — MUST be scrubbed before exec'ing
 * the workload so the passphrase / keyring identifiers / capsule paths do not
 * leak into the child's /proc/<pid>/environ or to any process the child spawns. */
static const char *const ELFDEC_SCRUB_ENV[] = {
    "ELFDEC_CODE",
    "ELFDEC_KEYID",
    "ELFDEC_LABEL",
    "ELFDEC_KEYPATH",
    "ELFDEC_CAP",          /* reserved name; scrubbed defensively */
    "ELFDEC_ALLOW_TRACE",  /* D-18 dev escape hatch — workload must not inherit */
    NULL
};

/* Loader/interpreter tampering vars. We strip these from BOTH our own
 * environment (early in main, via unsetenv) AND from the workload's envp
 * (via build_clean_envp). Reason: a hostile parent could set LD_PRELOAD
 * to interpose libsodium, and even though we typically build elfdec-run
 * with STATIC=1, the workload itself is dynamically linked and would
 * inherit the var. This is bar-raising defense-in-depth (root with /proc
 * access wins anyway), not a security guarantee. */
static const char *const LOADER_SCRUB_ENV[] = {
    /* Dynamic linker injection (glibc + macOS for portability) */
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG", "LD_PROFILE",
    "GCONV_PATH",                       /* glibc iconv arbitrary .so load */
    "HOSTALIASES",                      /* hostname resolution hijack */
    "LOCPATH", "NLSPATH",               /* locale/message catalog injection */
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    /* Interpreter startup injection (workload could be a script) */
    "BASH_ENV", "ENV",
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "PERL5OPT", "PERL5LIB",
    "RUBYOPT", "RUBYLIB",
    "_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS",
    /* Shell behavior hijack */
    "CDPATH", "GLOBIGNORE",
    NULL
};

/* Build a NULL-terminated envp array from `environ`, omitting any entry whose
 * NAME (text before '=') matches ELFDEC_SCRUB_ENV. Pointers reference the
 * existing strings in `environ`; the caller frees only the outer array. */
static char **build_clean_envp(void) {
    size_t n = 0;
    if (environ) while (environ[n]) n++;
    char **out = (char**)calloc(n + 1, sizeof(char*));
    if (!out) return NULL;
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        const char *e = environ[i];
        const char *eq = strchr(e, '=');
        size_t name_len = eq ? (size_t)(eq - e) : strlen(e);
        int skip = 0;
        for (size_t j = 0; ELFDEC_SCRUB_ENV[j] && !skip; j++) {
            size_t sl = strlen(ELFDEC_SCRUB_ENV[j]);
            if (name_len == sl && memcmp(e, ELFDEC_SCRUB_ENV[j], sl) == 0)
                skip = 1;
        }
        for (size_t j = 0; LOADER_SCRUB_ENV[j] && !skip; j++) {
            size_t sl = strlen(LOADER_SCRUB_ENV[j]);
            if (name_len == sl && memcmp(e, LOADER_SCRUB_ENV[j], sl) == 0)
                skip = 1;
        }
        if (!skip) out[k++] = (char*)e;
    }
    out[k] = NULL;
    return out;
}

/* best-effort overwrite before unlink in /dev/shm fallback */
static int wipe_file(int fd, off_t len) {
    if (len <= 0) return 0;
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    static unsigned char buf[65536];
    int ur = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (ur < 0) return -1;
    while (len > 0) {
        ssize_t r = read(ur, buf, sizeof buf);
        if (r <= 0) break;
        if ((off_t)r > len) r = (ssize_t)len;
        ssize_t w = write(fd, buf, r);
        if (w <= 0) break;
        len -= w;
    }
    close(ur);
    fsync(fd);
    return 0;
}

/* out = prefix + label (bounded, no format truncation) */
static int build_desc_safe(const char *prefix, const char *label,
                           char out[], size_t outsz) {
    size_t lp = strlen(prefix);
    size_t L  = strnlen(label, 4096);
    if (lp + L + 1 > outsz) { errno = ENAMETOOLONG; return -1; }
    memcpy(out, prefix, lp);
    memcpy(out + lp, label, L);
    out[lp + L] = '\0';
    return 0;
}

/* out = dir + "/" + leaf (dedup slash), with bounds checks */
static int safe_path_join(char out[], size_t outsz,
                          const char *dir, const char *leaf) {
    size_t dlen = strnlen(dir, PATH_MAX);
    size_t llen = strnlen(leaf, PATH_MAX);
    int need_slash = (dlen > 0 && dir[dlen-1] != '/');
    size_t tot = dlen + (need_slash?1:0) + llen + 1;
    if (tot > outsz) { errno = ENAMETOOLONG; return -1; }
    memcpy(out, dir, dlen);
    if (need_slash) out[dlen++] = '/';
    memcpy(out + dlen, leaf, llen);
    out[dlen + llen] = '\0';
    return 0;
}

/* instantiate @s; link @u into @s best-effort so search(@s, ...) can find @u keys */
static void ensure_session_keyring(void) {
    keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 1);
    (void)keyctl_link(KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING);
}

/* keyutils helpers */
static int read_key_by_id(key_serial_t key, unsigned char sk[32]) {
    void *buf = NULL;
    long n = keyctl_read_alloc(key, &buf);
    if (n < 0) return -1;
    if (n == 33 && ((unsigned char*)buf)[32] == '\n') n = 32;
    if (n != 32) { free(buf); errno = EINVAL; return -1; }
    memcpy(sk, buf, 32);
    free(buf);
    return 0;
}

static int read_priv_from_keyring_label(const char *label, unsigned char sk[32], key_serial_t *out_id) {
    char desc[256];
    if (build_desc_safe("elfdec:", label, desc, sizeof desc) != 0) return -1;
    ensure_session_keyring();
    key_serial_t key = keyctl_search(KEY_SPEC_SESSION_KEYRING, "user", desc, 0);
    if (key < 0) key = keyctl_search(KEY_SPEC_USER_KEYRING, "user", desc, 0);
    if (key < 0) return -1;
    if (out_id) *out_id = key;
    return read_key_by_id(key, sk);
}

/* simple file reader */
static int read_file_all(const char *path, unsigned char **buf, size_t *len) {
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    if (fseeko(f, 0, SEEK_END)!=0) { fclose(f); return -1; }
    off_t L = ftello(f); if (L < 0) { fclose(f); return -1; }
    if (fseeko(f, 0, SEEK_SET)!=0) { fclose(f); return -1; }
    unsigned char *p = (unsigned char*)malloc((size_t)L);
    if (!p) { fclose(f); return -1; }
    if (fread(p, 1, (size_t)L, f) != (size_t)L) { free(p); fclose(f); return -1; }
    fclose(f);
    if (buf) *buf = p; else free(p);
    if (len) *len = (size_t)L;
    return 0;
}

/* ===== capsule support ===== */
/* kcap_bin_hdr and kcap_derive_k are in kcap.h */

/* tiny base64 decode using libsodium */
static int b64_to_buf(const char *b64, unsigned char *out, size_t outmax, size_t *outlen) {
    size_t bin_len = 0;
    if (sodium_base642bin(out, outmax, b64, strlen(b64), NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) return -1;
    *outlen = bin_len; return 0;
}

/* micro JSON getters (very limited) */
static int json_get_b64(const char *js, const char *key, unsigned char *out, size_t outmax, size_t *outlen) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(js, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':'); if (!p) return -1;
    p++;  /* skip past ':' */
    while (*p==' '||*p=='\t') p++;
    if (*p!='"') return -1;
    p++;
    const char *q = strchr(p, '"'); if (!q) return -1;
    char *tmp = strndup(p, (size_t)(q-p));
    if (!tmp) return -1;
    int rc = b64_to_buf(tmp, out, outmax, outlen);
    free(tmp);
    return rc;
}
static int json_get_num_u64(const char *js, const char *key, uint64_t *val) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(js, pat); if (!p) return -1;
    p = strchr(p + strlen(pat), ':'); if (!p) return -1; p++;
    while (*p==' '||*p=='\t') p++;
    char *endp=NULL; unsigned long long v = strtoull(p, &endp, 10);
    if (endp==p) return -1;
    *val=(uint64_t)v;
    return 0;
}
static int json_get_num_u32(const char *js, const char *key, uint32_t *val) {
    uint64_t v=0; if (json_get_num_u64(js,key,&v)!=0) return -1; *val=(uint32_t)v; return 0;
}

/* decrypt capsule bytes -> out_sk[32] */
static int decrypt_capsule_buffer(const char *code, const unsigned char *buf, size_t blen, unsigned char out_sk[32]) {
    time_t now = time(NULL);

    /* KCAP3 dispatch: family-magic "KCAP" (4 bytes) + version 0x01 + project 0x01.
     * Per D-13 — disambiguate from legacy KCAP1\0 / KCAP2\0
     * by the 5th byte (version). */
    if (blen >= sizeof(struct kcap3_hdr)
        && memcmp(buf, KCAP_FAMILY_MAGIC, 4) == 0
        && buf[4] == KCAP_FAMILY_VERSION) {
        /* Propagate kcap3_unpack's errno (EINVAL / ENOMEM / EACCES) so the
         * caller's xdie message distinguishes "wrong code" (EACCES) from
         * "Argon2id ran out of memory" (ENOMEM) — AC-03-09 depends on this
         * to surface ENOMEM-flavored errors instead of "Permission denied". */
        if (kcap3_unpack(buf, blen, code, out_sk) != 0) {
            return -1;
        }
        (void)sodium_mlock(out_sk, 32);
        return 0;
    }

    if (blen >= sizeof(struct kcap_bin_hdr)) {
        const struct kcap_bin_hdr *H = (const struct kcap_bin_hdr*)buf;
        int is_v2 = (memcmp(H->magic, "KCAP2\0", 7) == 0);
        int is_v1 = (memcmp(H->magic, "KCAP1\0", 7) == 0);
        if (is_v1 || is_v2) {
            uint32_t ct_len = get_le32(H->ct_len);
            if (sizeof(*H) + (size_t)ct_len != blen) { errno=EINVAL; return -1; }
            uint64_t cap_t0  = get_le64(H->t0);
            uint32_t cap_ttl = get_le32(H->ttl);
            if (cap_ttl && (uint64_t)now > cap_t0 + cap_ttl) { errno=EPERM; return -1; }
            unsigned char K[32];
            if (is_v2) {
                if (kcap_derive_k_v2(code, H->salt, K) != 0) { errno=ENOMEM; return -1; }
            } else {
                kcap_derive_k(code, H->salt, K);
            }
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    out_sk, NULL, NULL,
                    buf + sizeof(*H), ct_len,
                    NULL, 0,
                    H->nonce, K) != 0) { sodium_memzero(K,32); errno=EACCES; return -1; }
            sodium_memzero(K,32);
            (void)sodium_mlock(out_sk, 32);
            return 0;
        }
    }

    /* JSON capsule fallback */
    if (blen > 0 && buf[0] == '{') {
        const char *js = (const char*)buf;
        unsigned char salt[16], nonce[24], ct[4096];
        size_t sl=0,nl=0,cl=0;
        uint64_t t0=0; uint32_t ttl=0; uint32_t v=2;
        if (json_get_b64(js,"salt",salt,sizeof salt,&sl)!=0 || sl!=16) { errno=EINVAL; return -1; }
        if (json_get_b64(js,"nonce",nonce,sizeof nonce,&nl)!=0 || nl!=24) { errno=EINVAL; return -1; }
        if (json_get_b64(js,"ct",ct,sizeof ct,&cl)!=0 || cl<16) { errno=EINVAL; return -1; }
        (void)json_get_num_u64(js,"t0",&t0);
        (void)json_get_num_u32(js,"ttl",&ttl);
        (void)json_get_num_u32(js,"v",&v);
        if (ttl && (uint64_t)now > t0 + ttl) { errno=EPERM; return -1; }
        unsigned char K[32];
        if (v == 1) {
            kcap_derive_k(code, salt, K);
        } else {
            if (kcap_derive_k_v2(code, salt, K) != 0) { errno=ENOMEM; return -1; }
        }
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                out_sk, NULL, NULL,
                ct, cl,
                NULL, 0,
                nonce, K) != 0) { sodium_memzero(K,32); errno=EACCES; return -1; }
        sodium_memzero(K,32);
        (void)sodium_mlock(out_sk, 32);
        return 0;
    }

    errno = EINVAL; return -1;
}

/* read capsule bytes from keyring elfdec_caps:<label> */
static int read_capsule_from_keyring_label(const char *label, unsigned char **buf, size_t *blen) {
    char desc[256];
    if (build_desc_safe("elfdec_caps:", label, desc, sizeof desc) != 0) return -1;
    ensure_session_keyring();
    key_serial_t key = keyctl_search(KEY_SPEC_SESSION_KEYRING, "user", desc, 0);
    if (key < 0) key = keyctl_search(KEY_SPEC_USER_KEYRING, "user", desc, 0);
    if (key < 0) return -1;
    long n = keyctl_read_alloc(key, (void**)buf);
    if (n < 0) return -1;
    *blen = (size_t)n; return 0;
}

/* ===== main ===== */

int main(int argc, char **argv){
    if (argc < 2) return xdie("usage: %s <file.elfenc> [args...]", argv[0]);

    /* Pre-init hardening: disable core dumps and block setuid escalation as
     * early as possible, before any sensitive material lives in this process.
     * (Was previously done after decryption — too late if we segfault during
     * unwrap.) */
    prctl(PR_SET_DUMPABLE, 0);
    prctl(PR_SET_NO_NEW_PRIVS, 1);

    /* Strip dynamic-loader / interpreter tampering vars from our own env
     * before any libsodium call. Note: by the time main() runs, glibc has
     * already honored LD_PRELOAD, so this does not protect elfdec-run from
     * a preload that was set when we were exec'd — STATIC=1 is the real
     * answer for that. What this does protect is anything we fork+exec
     * later, plus it makes our own getenv() lookups not see hostile values.
     * (build_clean_envp also strips these from the workload's envp.) */
    for (size_t j = 0; LOADER_SCRUB_ENV[j]; j++)
        (void)unsetenv(LOADER_SCRUB_ENV[j]);

    if (sodium_init() < 0) return xdie("sodium_init failed");

    /* D-18: refuse to run under a ptrace tracer before any sensitive work
     * (capsule unwrap / ELF decrypt / memfd write). Defense-in-depth only —
     * raises the bar against casual `gdb -p` and same-uid attaches; does NOT
     * defeat root via /proc manipulation or kernel rootkits. ELFDEC_ALLOW_TRACE=1
     * is the dev escape hatch (and is itself scrubbed before exec by D-17). */
    if (getenv("ELFDEC_ALLOW_TRACE") == NULL) {
        pid_t tp = get_tracer_pid();
        if (tp > 0) return xdie("refusing to run under tracer (TracerPid=%d)", (int)tp);
    }

    /* label selection */
    const char *label = getenv("ELFDEC_LABEL");
    char resolved[PATH_MAX];
    if (!label) {
        if (realpath(argv[1], resolved)) label = resolved;
        else label = argv[1];
    }

    /* key dir defaults */
    const char *keypath = getenv("ELFDEC_KEYPATH");
    char defhome[PATH_MAX]; const char *home = getenv("HOME"); if (!home) home = "";
    if (safe_path_join(defhome, sizeof defhome, home, ".elfenc") != 0)
        return xdie("HOME too long");

    /* final secret/public */
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    int have_priv = 0;

    /* 1) Capsule path if ELFDEC_CODE is set */
    const char *code = getenv("ELFDEC_CODE");
    if (code && *code) {
        unsigned char *cap=NULL; size_t clen=0; int found=0;
        if (read_capsule_from_keyring_label(label, &cap, &clen) == 0) {
            found = 1;
        } else if (keypath && *keypath) {
            char p1[PATH_MAX]; if (safe_path_join(p1, sizeof p1, keypath, "capsule.bin") != 0) p1[0]='\0';
            char p2[PATH_MAX]; if (safe_path_join(p2, sizeof p2, keypath, "capsule.json")!= 0) p2[0]='\0';
            if (p1[0] && read_file_all(p1, &cap, &clen) == 0) found = 1;
            else if (p2[0] && read_file_all(p2, &cap, &clen) == 0) found = 1;
        }
        if (found) {
            if (decrypt_capsule_buffer(code, cap, clen, sk) == 0) {
                if (crypto_scalarmult_base(pk, sk) != 0) return xdie("capsule: derive pub failed");
                have_priv = 1;
            } else {
                sodium_memzero(cap, clen); free(cap);
                return xdie("capsule decrypt failed");
            }
            sodium_memzero(cap, clen); free(cap);
        } else {
            fprintf(stderr, "warning: ELFDEC_CODE set but no capsule found (keyring or %s/{capsule.bin,capsule.json})\n",
                    keypath?keypath:"(unset)");
        }
    }

    /* 2) Keyring (by ID or label) */
    if (!have_priv) {
        const char *keyid_env = getenv("ELFDEC_KEYID");
        if (keyid_env && *keyid_env) {
            char *endp=NULL; long long v=strtoll(keyid_env,&endp,10);
            if (endp && *endp=='\0' && v>0) {
                if (read_key_by_id((key_serial_t)v, sk)==0) {
                    if (crypto_scalarmult_base(pk, sk) != 0) return xdie("keyid: derive pub failed");
                    have_priv=1;
                } else {
                    fprintf(stderr, "warning: ELFDEC_KEYID read failed: %s\n", strerror(errno));
                }
            } else {
                fprintf(stderr, "warning: invalid ELFDEC_KEYID '%s'\n", keyid_env);
            }
        }
    }
    if (!have_priv) {
        key_serial_t kid=-1;
        if (read_priv_from_keyring_label(label, sk, &kid)==0) {
            if (crypto_scalarmult_base(pk, sk) != 0) return xdie("keyring: derive pub failed");
            have_priv=1;
        }
    }

    /* 3) ELFDEC_KEYPATH directory */
    if (!have_priv && keypath && *keypath) {
        char p_priv[PATH_MAX];
        if (safe_path_join(p_priv, sizeof p_priv, keypath, "priv.bin") != 0)
            return xdie("ELFDEC_KEYPATH too long");
        if (access(p_priv, R_OK)==0) {
            FILE *f=fopen(p_priv,"rb"); if(!f) return xdie("open %s", p_priv);
            if (fread(sk,1,sizeof sk,f)!=sizeof sk){ fclose(f); return xdie("read %s", p_priv); }
            fclose(f);
            if (crypto_scalarmult_base(pk, sk) != 0) return xdie("keypath: derive pub failed");
            have_priv=1;
        }
    }

    /* 4) default ~/.elfenc */
    if (!have_priv) {
        char p_priv[PATH_MAX];
        if (safe_path_join(p_priv, sizeof p_priv, defhome, "priv.bin") != 0)
            return xdie("~/.elfenc path too long");
        FILE *f=fopen(p_priv,"rb"); if(!f) return xdie("open %s", p_priv);
        if (fread(sk,1,sizeof sk,f)!=sizeof sk){ fclose(f); return xdie("read %s", p_priv); }
        fclose(f);
        if (crypto_scalarmult_base(pk, sk) != 0) return xdie("derive pub failed");
        have_priv=1;
    }

    if (!have_priv) return xdie("no private key available");

    /* ===== decrypt ELFENC ===== */
    int infd = open(argv[1], O_RDONLY|O_CLOEXEC);
    if (infd<0) return xdie("open %s", argv[1]);

    struct elfenc_hdr H;
    if (read_exact(infd, &H, sizeof H)) return xdie("short read header");
    if (memcmp(H.magic,"ELFENC1",7)!=0 || H.magic[7] != '\0') return xdie("bad magic");
    uint64_t file_clen = get_le64(H.clen);
    if (file_clen < crypto_box_SEALBYTES) return xdie("bad clen");

    size_t clen = (size_t)file_clen;
    unsigned char *cipher = (unsigned char*)malloc(clen);
    if (!cipher) return xdie("oom cipher");
    /* Best-effort: pin both the ciphertext and the soon-to-exist plaintext
     * out of swap. Failure is
     * non-fatal (RLIMIT_MEMLOCK on hardened distros / unprivileged users). */
    (void)sodium_mlock(cipher, clen);
    if (read_exact(infd, cipher, clen)) return xdie("short read body");
    close(infd);

    size_t plen = clen - crypto_box_SEALBYTES;
    unsigned char *plain = (unsigned char*)malloc(plen);
    if (!plain) return xdie("oom plain");
    (void)sodium_mlock(plain, plen);
    if (crypto_box_seal_open(plain, cipher, clen, pk, sk) != 0) return xdie("decrypt failed");

    int fd = memfd_create_compat("elfdec", MFD_CLOEXEC | MFD_ALLOW_SEALING
#ifdef MFD_EXEC
                                 | MFD_EXEC
#endif
                                 );
    char tmp_path[128] = {0};
    int use_tmp = 0;

    if (fd < 0) {
        snprintf(tmp_path, sizeof tmp_path, "/dev/shm/elfdec-%d", getpid());
        fd = open(tmp_path, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC, 0700);
        if (fd < 0) return xdie("memfd+fallback failed");
        use_tmp = 1;
    }

    if (write(fd, plain, plen) != (ssize_t)plen) return xdie("write payload");
    sodium_memzero(plain, plen);
    (void)sodium_munlock(plain, plen);   /* sodium_munlock implies memzero */
    free(plain);
    sodium_memzero(cipher, clen);
    (void)sodium_munlock(cipher, clen);
    free(cipher);
    sodium_memzero(sk, sizeof sk);

#ifdef F_ADD_SEALS
    int seals = F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE;
    if (fcntl(fd, F_ADD_SEALS, seals) < 0)
        fprintf(stderr, "warning: F_ADD_SEALS failed (%s), fexecve may fail\n", strerror(errno));
#endif
    fchmod(fd, 0700);
    lseek(fd, 0, SEEK_SET);

    int child_argc = argc - 1;
    char **child_argv = (char**)calloc(child_argc + 1, sizeof(char*));
    if (!child_argv) return xdie("oom argv");
    for (int i=0;i<child_argc;i++) child_argv[i] = argv[i+1];
    child_argv[child_argc] = NULL;

    /* D-17: scrub ephrun-internal env vars from the workload's environment. */
    char **clean_envp = build_clean_envp();
    if (!clean_envp) return xdie("oom envp");

    if (!use_tmp) {
        /* Memfd path: try fexecve. On any non-ETXTBSY error, fail closed (D-16). */
        fexecve(fd, child_argv, clean_envp);
        int saved = errno;
        if (saved != ETXTBSY) {
            errno = saved;
            return xdie("fexecve failed");
        }
        /* ETXTBSY: copy memfd → /dev/shm and fall through to the unified
         * hardened-exec block below. */
        snprintf(tmp_path, sizeof tmp_path, "/dev/shm/elfdec-%d", getpid());
        int tfd = open(tmp_path, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC, 0700);
        if (tfd < 0) { errno = saved; return xdie("open %s", tmp_path); }
        lseek(fd, 0, SEEK_SET);
        char b[65536]; ssize_t r; int copy_ok = 1;
        while ((r = read(fd, b, sizeof b)) > 0) {
            if (write(tfd, b, r) != r) { copy_ok = 0; break; }
        }
        if (r < 0) copy_ok = 0;
        if (fsync(tfd) != 0) copy_ok = 0;
        if (!copy_ok) {
            struct stat st_err;
            if (fstat(tfd, &st_err) == 0) wipe_file(tfd, st_err.st_size);
            close(tfd); unlink(tmp_path); close(fd);
            return xdie("/dev/shm copy failed");
        }
        close(fd);
        fd = tfd;
        use_tmp = 1;  /* fall through */
    }

    /* Unified hardened exec for both /dev/shm fallback paths (D-16):
     *   (i)  initial use_tmp=1 from memfd_create unavailable, or
     *   (ii) fall-through from fexecve→ETXTBSY above.
     * Open a read-only fd, close the writer, unlink the path, then
     * execveat(rofd, "", argv, envp, AT_EMPTY_PATH). The plaintext file is
     * no longer reachable on the filesystem when the workload starts.
     * On exec failure, wipe via /proc/self/fd/N (path is gone). */
    fsync(fd);
    struct stat st;
    if (fstat(fd, &st) != 0) {
        wipe_file(fd, 0);
        close(fd); unlink(tmp_path);
        return xdie("fstat tmp");
    }
    int ro_fd = open(tmp_path, O_RDONLY|O_CLOEXEC);
    if (ro_fd < 0) {
        wipe_file(fd, st.st_size);
        close(fd); unlink(tmp_path);
        return xdie("reopen tmp ro");
    }
    close(fd);            /* writer closed → no ETXTBSY on execveat */
    unlink(tmp_path);     /* file persists via ro_fd; no plaintext path on disk */

    execveat_compat(ro_fd, "", child_argv, clean_envp, AT_EMPTY_PATH);
    int saved_errno = errno;

    /* exec failed — wipe via /proc/self/fd/N (the path is already unlinked) */
    char proc_path[64];
    snprintf(proc_path, sizeof proc_path, "/proc/self/fd/%d", ro_fd);
    int wfd = open(proc_path, O_RDWR | O_CLOEXEC);
    if (wfd >= 0) { wipe_file(wfd, st.st_size); close(wfd); }
    close(ro_fd);
    errno = saved_errno;
    return xdie("execveat failed");
}
