/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 *
 * test_fexecve_shim.c — LD_PRELOAD shim that fails fexecve() with a
 * caller-chosen errno. Used by test.sh to drive AC-03-04 / AC-03-05.
 *
 * Build (driven by test.sh):
 *   gcc -fPIC -shared -O2 test_fexecve_shim.c -ldl -o libtest_fexecve_shim.so
 *
 * Trigger:
 *   ELFDEC_TEST_FEXECVE_ERRNO=<errno-int> LD_PRELOAD=./libtest_fexecve_shim.so ...
 *
 * Why this exists: provoking ETXTBSY from a real fexecve() on a sealed
 * memfd is kernel-version-dependent and not reliable in a regression test.
 * A shim makes the /dev/shm fallback paths deterministic.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>

int fexecve(int fd, char *const argv[], char *const envp[]) {
    const char *e = getenv("ELFDEC_TEST_FEXECVE_ERRNO");
    if (e && *e) {
        errno = atoi(e);
        return -1;
    }
    static int (*real)(int, char *const[], char *const[]) = NULL;
    if (!real) real = (int(*)(int, char*const[], char*const[]))dlsym(RTLD_NEXT, "fexecve");
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, argv, envp);
}
