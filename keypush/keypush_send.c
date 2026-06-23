/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 *
// keypush_send.c — Cross-platform (Linux/macOS) UDP sender for keypushd
// Sends a sealed box with {"label","ttl","token","key_b64"} to the receiver.
// Deps: libsodium (brew install libsodium) and a C toolchain.
//
// Usage:
//   head -c 32 /dev/urandom | ./keypush_send \
//     --ip 10.8.0.2 --port 41235 --srv-pk-b64 BASE64... \
//     --token K3J7... --label prod/hello --ttl 300 --wait-ack
//
// Notes:
// - Reads EXACTLY 32 bytes from stdin; fails otherwise.
// - ACK/NAK is a tiny JSON from receiver; we just print it if --wait-ack.
//
// Build: see Makefile below.
*/
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/types.h>
#endif

static void die(const char *msg) { perror(msg); exit(1); }
static void die_msg(const char *msg) { fprintf(stderr, "%s\n", msg); exit(1); }

typedef struct {
  const char *ip;
  int port;
  const char *srv_pk_b64;
  const char *token;
  const char *label;
  int ttl;
  int wait_ack;
} cfg_t;

static void usage(const char *argv0) {
  fprintf(stderr,
    "Usage: %s --ip IP --port N --srv-pk-b64 B64 --token T --label L [--ttl S] [--wait-ack]\n"
    "Reads exactly 32 bytes from stdin and sends sealed payload over UDP.\n", argv0);
}

int main(int argc, char **argv) {
  cfg_t cfg = {.ip=NULL,.port=0,.srv_pk_b64=NULL,.token=NULL,.label=NULL,.ttl=300,.wait_ack=0};
  for (int i=1;i<argc;i++){
    if (!strcmp(argv[i],"--ip") && i+1<argc) cfg.ip = argv[++i];
    else if (!strcmp(argv[i],"--port") && i+1<argc) cfg.port = atoi(argv[++i]);
    else if (!strcmp(argv[i],"--srv-pk-b64") && i+1<argc) cfg.srv_pk_b64 = argv[++i];
    else if (!strcmp(argv[i],"--token") && i+1<argc) cfg.token = argv[++i];
    else if (!strcmp(argv[i],"--label") && i+1<argc) cfg.label = argv[++i];
    else if (!strcmp(argv[i],"--ttl") && i+1<argc) cfg.ttl = atoi(argv[++i]);
    else if (!strcmp(argv[i],"--wait-ack")) cfg.wait_ack = 1;
    else { usage(argv[0]); return 1; }
  }
  if (!cfg.ip || cfg.port<=0 || !cfg.srv_pk_b64 || !cfg.token || !cfg.label) {
    usage(argv[0]); return 1;
  }

  // Read exactly 32 bytes from stdin
  unsigned char key32[32]; size_t got = 0;
  while (got < sizeof(key32)) {
    ssize_t n = read(STDIN_FILENO, key32 + got, sizeof(key32) - got);
    if (n < 0) die("read(stdin)");
    if (n == 0) break;
    got += (size_t)n;
  }
  if (got != 32) { fprintf(stderr, "expecting EXACTLY 32 bytes on stdin\n"); exit(1); }

  if (sodium_init() < 0) die_msg("sodium_init failed");

  // Decode server public key (base64 original)
  unsigned char srv_pk[crypto_box_PUBLICKEYBYTES]; size_t outlen = 0;
  if (sodium_base642bin(srv_pk, sizeof(srv_pk),
        cfg.srv_pk_b64, strlen(cfg.srv_pk_b64),
        NULL, &outlen, NULL, sodium_base64_VARIANT_ORIGINAL) != 0 || outlen != sizeof(srv_pk)) {
    die_msg("invalid --srv-pk-b64");
  }

  // Build small JSON payload
  // key_b64 length for 32 bytes with standard base64 = 44 including padding
  char key_b64[64];
  sodium_bin2base64(key_b64, sizeof(key_b64), key32, sizeof(key32), sodium_base64_VARIANT_ORIGINAL);

  /* Build JSON payload with minimal escaping for label (may contain \ or ") */
  char json[1024];
  int pos = 0;
  pos += snprintf(json + pos, sizeof(json) - (size_t)pos, "{\"label\":\"");
  for (const char *p = cfg.label; *p && pos < (int)sizeof(json) - 4; ++p) {
    if (*p == '\\' || *p == '"') json[pos++] = '\\';
    json[pos++] = *p;
  }
  int tail = snprintf(json + pos, sizeof(json) - (size_t)pos,
           "\",\"ttl\":%d,\"token\":\"%s\",\"key_b64\":\"%s\"}",
           cfg.ttl, cfg.token, key_b64);
  if (tail < 0 || (size_t)(pos + tail) >= sizeof(json)) {
    sodium_memzero(key32, sizeof(key32));
    die_msg("JSON payload too large (label too long?)");
  }
  pos += tail;

  // Seal to server public key
  size_t ct_len = crypto_box_SEALBYTES + (size_t)pos;
  unsigned char *ct = (unsigned char*)malloc(ct_len);
  if (!ct) die("malloc");
  if (crypto_box_seal(ct, (const unsigned char*)json, (size_t)pos, srv_pk) != 0) {
    free(ct); die_msg("crypto_box_seal failed");
  }
  sodium_memzero(key32, sizeof(key32));

  // UDP send
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) { free(ct); die("socket"); }

  struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons((uint16_t)cfg.port);
  if (inet_pton(AF_INET, cfg.ip, &sa.sin_addr) != 1) {
    close(fd); free(ct); die_msg("inet_pton failed for --ip");
  }

  ssize_t sent = sendto(fd, ct, ct_len, 0, (struct sockaddr*)&sa, sizeof(sa));
  if (sent < 0 || (size_t)sent != ct_len) {
    close(fd); free(ct); die("sendto");
  }

  if (cfg.wait_ack) {
    struct timeval tv; tv.tv_sec = 3; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    unsigned char buf[2048];
    ssize_t n = recvfrom(fd, buf, sizeof(buf)-1, 0, NULL, NULL);
    if (n > 0) {
      buf[n] = 0;
      // Just print the JSON line from server
      fwrite(buf, 1, (size_t)n, stdout);
      fputc('\n', stdout);
    }
  }

  close(fd);
  free(ct);
  return 0;
}
