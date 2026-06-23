/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 *
 * env_dump.c — Test workload for AC-03-07. Prints its own environment
 * (read from /proc/self/environ) one variable per line. test.sh greps the
 * output to verify the ELFDEC_* scrub took effect.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/proc/self/environ", "rb");
    if (!f) { perror("fopen /proc/self/environ"); return 1; }
    int c, prev = -1;
    while ((c = fgetc(f)) != EOF) {
        if (c == 0) { fputc('\n', stdout); }
        else        { fputc(c, stdout);  }
        prev = c;
    }
    if (prev != 0 && prev != -1) fputc('\n', stdout);
    fclose(f);
    return 0;
}
