/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 */
#include <stdio.h>
int main(int argc, char **argv) {
    puts("hello from encrypted ELF!");
    for (int i=0;i<argc;i++) printf("argv[%d]=%s\n", i, argv[i]);
    return 0;
}
