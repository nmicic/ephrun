/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 */
#include <keyutils.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main() {
  key_serial_t k = keyctl_search(KEY_SPEC_USER_KEYRING,"user","elfdec:prod/hello",0);
  if (k < 0) { perror("search @u"); return 1; }
  void *buf=NULL; long n=keyctl_read_alloc(k,&buf);
  if (n<0) { perror("read"); return 1; }
  printf("bytes=%ld\n", n);
  free(buf);
  return 0;
}

