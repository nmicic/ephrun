/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 */
// keypushd.c — One-shot UDP receiver: sealed box → keyctl @s/@u with TTL
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <keyutils.h>
#include <netinet/in.h>
#include <signal.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* --- Compatibility: some keyutils headers might miss KEYCTL_SET_TIMEOUT --- */
#ifndef KEYCTL_SET_TIMEOUT
#define KEYCTL_SET_TIMEOUT 15          /* linux/keyctl.h value */
#endif

/* --------------------------- Minimal JSMN (MIT) --------------------------- */
typedef enum { JSMN_UNDEFINED = 0, JSMN_OBJECT = 1, JSMN_ARRAY = 2,
               JSMN_STRING = 3, JSMN_PRIMITIVE = 4 } jsmntype_t;
typedef struct {
  jsmntype_t type;
  int start;
  int end;
  int size;
#ifdef JSMN_PARENT_LINKS
  int parent;
#endif
} jsmntok_t;
typedef struct {
  unsigned int pos; unsigned int toknext; int toksuper;
} jsmn_parser;

static void jsmn_init(jsmn_parser *parser) { parser->pos = 0; parser->toknext = 0; parser->toksuper = -1; }
static jsmntok_t *jsmn_alloc_token(jsmn_parser *parser, jsmntok_t *tokens, size_t num_tokens){
  if (parser->toknext >= num_tokens) return NULL;
  jsmntok_t *tok = &tokens[parser->toknext++];
  tok->start = tok->end = -1; tok->size = 0; tok->type = JSMN_UNDEFINED;
#ifdef JSMN_PARENT_LINKS
  tok->parent = -1;
#endif
  return tok;
}
static void jsmn_fill_token(jsmntok_t *token, jsmntype_t type, int start, int end){
  token->type = type; token->start = start; token->end = end; token->size = 0;
}
static int jsmn_parse_primitive(jsmn_parser *parser, const char *js, size_t len, jsmntok_t *tokens, size_t num_tokens){
  int start = (int)parser->pos;
  for (; parser->pos < (unsigned int)len; parser->pos++){
    switch (js[parser->pos]) {
      case '\t': case '\r': case '\n': case ' ': case ',': case ']': case '}':
        goto found;
    default:
      if (js[parser->pos] < 32 || js[parser->pos] >= 127) { parser->pos = start; return -2; }
    }
  }
found:
  if (tokens == NULL) { parser->pos--; return 0; }
  jsmntok_t *token = jsmn_alloc_token(parser, tokens, num_tokens);
  if (token == NULL) { parser->pos = start; return -1; }
  jsmn_fill_token(token, JSMN_PRIMITIVE, start, (int)parser->pos);
  parser->pos--; return 0;
}
static int jsmn_parse_string(jsmn_parser *parser, const char *js, size_t len, jsmntok_t *tokens, size_t num_tokens){
  int start = (int)parser->pos;
  parser->pos++;
  for (; parser->pos < (unsigned int)len; parser->pos++){
    char c = js[parser->pos];
    if (c == '\"'){
      if (tokens == NULL) return 0;
      jsmntok_t *token = jsmn_alloc_token(parser, tokens, num_tokens);
      if (token == NULL) { parser->pos = start; return -1; }
      jsmn_fill_token(token, JSMN_STRING, start+1, (int)parser->pos); return 0;
    }
    if (c == '\\' && parser->pos + 1 < (unsigned int)len) parser->pos++;
  }
  parser->pos = start; return -3;
}
static int jsmn_parse(jsmn_parser *parser, const char *js, size_t len, jsmntok_t *tokens, unsigned int num_tokens){
  int r; int i; jsmntok_t *token;
  for (; parser->pos < (unsigned int)len; parser->pos++){
    char c = js[parser->pos];
    switch (c){
      case '{': case '[':
        token = jsmn_alloc_token(parser, tokens, num_tokens);
        if (token == NULL) return -1;
        token->type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
        token->start = (int)parser->pos; parser->toksuper = (int)parser->toknext - 1; break;
      case '}': case ']':
        for (i = (int)parser->toknext - 1; i >= 0; i--){
          token = &tokens[i];
          if (token->start != -1 && token->end == -1){
            token->end = (int)parser->pos + 1; break;
          }
        }
        if (i == -1) return -2;
        for (; i >= 0; i--){
          token = &tokens[i];
          if (token->start != -1 && token->end == -1){
            parser->toksuper = i; break;
          }
        }
        break;
      case '\"':
        r = jsmn_parse_string(parser, js, len, tokens, num_tokens);
        if (r < 0) return r;
        if (parser->toksuper != -1) tokens[parser->toksuper].size++;
        break;
      case '\t': case '\r': case '\n': case ' ': case ':': case ',':
        break;
      default:
        r = jsmn_parse_primitive(parser, js, len, tokens, num_tokens);
        if (r < 0) return r;
        if (parser->toksuper != -1) tokens[parser->toksuper].size++;
        break;
    }
  }
  for (i = (int)parser->toknext - 1; i >= 0; i--){
    if (tokens[i].start != -1 && tokens[i].end == -1) return -2;
  }
  return (int)parser->toknext;
}
/* --------------------------- Base32 (RFC4648, no padding) ------------------ */
static const char B32_ALPH[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static void base32_nopad(const unsigned char *in, size_t len, char *out, size_t outlen){
  size_t i=0, bits=0; unsigned int buffer=0; size_t o=0;
  while (i < len){
    buffer = (buffer << 8) | in[i++]; bits += 8;
    while (bits >= 5){
      out[o++] = B32_ALPH[(buffer >> (bits - 5)) & 0x1F];
      bits -= 5;
    }
  }
  if (bits > 0){
    out[o++] = B32_ALPH[(buffer << (5 - bits)) & 0x1F];
  }
  if (o < outlen) out[o] = '\0';
}

/* --------------------------- Helpers -------------------------------------- */
static void die(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
  fputc('\n', stderr); exit(1);
}
static void warnx(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
  fputc('\n', stderr);
}
static void set_core_rlimit_zero(void){
  struct rlimit rl = {0,0};
  setrlimit(RLIMIT_CORE, &rl);
}
static uint64_t now_sec(void){ return (uint64_t)time(NULL); }

static void json_escape(const char *in, char *out, size_t outsz){
  size_t o=0;
  for (size_t i=0; in[i] && o+2 < outsz; i++){
    unsigned char c = (unsigned char)in[i];
    if (c=='"' || c=='\\'){ if (o+2 >= outsz) break; out[o++]='\\'; out[o++]=c; }
    else if (c >= 0x20) { out[o++]=c; }
    else { /* skip control */ }
  }
  if (o<outsz) out[o]='\0';
}
static int json_field_eq(const char *js, jsmntok_t *tok, const char *s){
  int l = tok->end - tok->start; return (int)strlen(s)==l && strncmp(js+tok->start, s, l)==0;
}

/* --------------------------- Program -------------------------------------- */
typedef struct {
  const char *bind_ip;
  int port;
  const char *def_label;
  int ttl_max;
  int window_sec;
  int detach;
  int link_user;
} cfg_t;

static void usage(const char *argv0){
  fprintf(stderr,
    "Usage: %s --bind IP [--port N] [--label L] [--ttl 300] [--window 60] [--detach] [--link-user]\n"
    "Prints bootstrap JSON then accepts one sealed payload.\n", argv0);
}

static int sock_bind_udp(const char *ip, int port){
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) die("socket: %s", strerror(errno));
  struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
  sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) die("inet_pton failed for %s", ip);
  if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) die("bind: %s", strerror(errno));
  if (port == 0){
    socklen_t sl = sizeof(sa);
    if (getsockname(fd, (struct sockaddr*)&sa, &sl) == 0) port = ntohs(sa.sin_port);
  }
  return fd;
}

static void daemonize_after_print(void){
  pid_t p = fork();
  if (p < 0) die("fork");
  if (p > 0) exit(0);
  if (setsid() < 0) die("setsid");
  p = fork(); if (p < 0) die("fork2"); if (p > 0) exit(0);
  int nullfd = open("/dev/null", O_RDWR);
  if (nullfd >= 0){
    dup2(nullfd, 0); dup2(nullfd, 1); dup2(nullfd, 2);
    if (nullfd > 2) close(nullfd);
  }
  umask(077);
}


static key_serial_t add_key_to_keyring(const char *label, size_t label_len,
                                       const unsigned char key32[32], int ttl, int link_user){
  char desc[256];

  // Build "elfdec:<label>" safely.
  const char prefix[] = "elfdec:";
  const size_t prefix_len = sizeof(prefix) - 1;      // 7
  const size_t max_label = sizeof(desc) - 1 - prefix_len;

  size_t L = label_len;
  if (L > max_label) L = max_label;

  memcpy(desc, prefix, prefix_len);
  memcpy(desc + prefix_len, label, L);
  desc[prefix_len + L] = '\0';

  key_serial_t dest = KEY_SPEC_SESSION_KEYRING; // always @s
  key_serial_t serial = add_key("user", desc, key32, 32, dest);
  if (serial == -1) die("add_key: %s", strerror(errno));

  // TTL (seconds)
  if (keyctl(KEYCTL_SET_TIMEOUT, serial, (unsigned long)ttl) == -1){
    warnx("keyctl timeout failed (ignored on old kernels): %s", strerror(errno));
  }

  // Permissions mask: 0x3f030000 (possessor all, owner view+read)
  unsigned int perm = 0x3f030000U;
  if (keyctl(KEYCTL_SETPERM, serial, perm) == -1){
    warnx("keyctl setperm failed: %s", strerror(errno));
  }

  if (link_user){
    if (keyctl_link(serial, KEY_SPEC_USER_KEYRING) == -1){
      warnx("keyctl link to @u failed: %s", strerror(errno));
    }
  }
  return serial;
}

static void send_json(int fd, const struct sockaddr_in *peer, const char *s){
  sendto(fd, s, strlen(s), 0, (const struct sockaddr*)peer, sizeof(*peer));
}

// Extract string value by key using JSMN (flat object)
static int json_get_str(const char *js, jsmntok_t *toks, int ntok, const char *key, const char **out, int *outlen){
  if (ntok <= 0 || toks[0].type != JSMN_OBJECT) return -1;
  for (int i=1; i<ntok; i++){
    if (toks[i].type == JSMN_STRING && json_field_eq(js, &toks[i], key)){
      jsmntok_t *v = &toks[i+1];
      if (v->type != JSMN_STRING) return -1;
      *out = js + v->start; *outlen = v->end - v->start; return 0;
    }
  }
  return -1;
}
static int json_get_int(const char *js, jsmntok_t *toks, int ntok, const char *key, int *out){
  if (ntok <= 0 || toks[0].type != JSMN_OBJECT) return -1;
  for (int i=1; i<ntok; i++){
    if (toks[i].type == JSMN_STRING && json_field_eq(js, &toks[i], key)){
      jsmntok_t *v = &toks[i+1];
      if (v->type != JSMN_PRIMITIVE) return -1;
      *out = atoi(js + v->start); return 0;
    }
  }
  return -1;
}

int main(int argc, char **argv){
  cfg_t cfg = {.bind_ip=NULL,.port=0,.def_label=NULL,.ttl_max=300,.window_sec=60,.detach=0,.link_user=0};
  for (int i=1;i<argc;i++){
    if (!strcmp(argv[i],"--bind") && i+1<argc) { cfg.bind_ip=argv[++i]; }
    else if (!strcmp(argv[i],"--port") && i+1<argc) { cfg.port=atoi(argv[++i]); }
    else if (!strcmp(argv[i],"--label") && i+1<argc) { cfg.def_label=argv[++i]; }
    else if (!strcmp(argv[i],"--ttl") && i+1<argc) { cfg.ttl_max=atoi(argv[++i]); }
    else if (!strcmp(argv[i],"--window") && i+1<argc) { cfg.window_sec=atoi(argv[++i]); }
    else if (!strcmp(argv[i],"--detach")) { cfg.detach=1; }
    else if (!strcmp(argv[i],"--link-user")) { cfg.link_user=1; }
    else { 
      fprintf(stderr,"Unknown arg: %s\n", argv[i]);
      usage(argv[0]); 
      return 1; 
    }
  }
  if (!cfg.bind_ip){ usage(argv[0]); return 1; }

  signal(SIGPIPE, SIG_IGN);
  set_core_rlimit_zero();
  umask(077);

  if (sodium_init() < 0) die("sodium_init failed");

  unsigned char sk[crypto_box_SECRETKEYBYTES];
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  crypto_box_keypair(pk, sk);

  unsigned char tokraw[16]; randombytes_buf(tokraw, sizeof(tokraw));
  char token_b32[64]; memset(token_b32, 0, sizeof(token_b32));
  base32_nopad(tokraw, sizeof(tokraw), token_b32, sizeof(token_b32));
  sodium_memzero(tokraw, sizeof(tokraw));

  int fd = sock_bind_udp(cfg.bind_ip, cfg.port);

  struct sockaddr_in sa; socklen_t sl=sizeof(sa); memset(&sa,0,sizeof(sa));
  if (getsockname(fd, (struct sockaddr*)&sa, &sl) < 0) die("getsockname: %s", strerror(errno));
  int bound_port = ntohs(sa.sin_port);

  uint64_t expires = now_sec() + (uint64_t)cfg.window_sec;

  char pk_b64[256];
  sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, sizeof(pk),
                    sodium_base64_VARIANT_ORIGINAL);

  {
    char ip_esc[128]; json_escape(cfg.bind_ip, ip_esc, sizeof(ip_esc));
    printf("{\"ip\":\"%s\",\"port\":%d,\"srv_pk\":\"%s\",\"token\":\"%s\",\"expires\":%" PRIu64 "}\n",
           ip_esc, bound_port, pk_b64, token_b32, expires);
    fflush(stdout);
  }

  if (cfg.detach) daemonize_after_print();

  struct timeval tv; tv.tv_sec = cfg.window_sec; tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  unsigned char rxbuf[65536];
  struct sockaddr_in peer; socklen_t peersz=sizeof(peer);

  ssize_t n = recvfrom(fd, rxbuf, sizeof(rxbuf), 0, (struct sockaddr*)&peer, &peersz);
  if (n < 0){
    close(fd); sodium_memzero(sk, sizeof(sk)); return 0;
  }

  if ((size_t)n < crypto_box_SEALBYTES){
    const char *nak = "{\"ok\":false,\"err\":\"too_short\"}";
    send_json(fd, &peer, nak); close(fd); sodium_memzero(sk, sizeof(sk)); return 0;
  }
  unsigned char plain[65536];
  size_t plainlen = (size_t)n - crypto_box_SEALBYTES;
  if (crypto_box_seal_open(plain, rxbuf, (unsigned long long)n, pk, sk) != 0){
    const char *nak = "{\"ok\":false,\"err\":\"decrypt\"}";
    send_json(fd, &peer, nak); close(fd); sodium_memzero(sk, sizeof(sk)); return 0;
  }
  sodium_memzero(sk, sizeof(sk));

  jsmn_parser p; jsmn_init(&p);
  jsmntok_t toks[64];
  int ntok = jsmn_parse(&p, (const char*)plain, plainlen, toks, 64);
  if (ntok < 1 || toks[0].type != JSMN_OBJECT){
    const char *nak = "{\"ok\":false,\"err\":\"bad_json\"}";
    send_json(fd, &peer, nak); close(fd); return 0;
  }

  const char *label=NULL, *token=NULL, *key_b64=NULL;
  int labellen=0, tokenlen=0, keyb64len=0, ttl_req=cfg.ttl_max;
  if (json_get_str((char*)plain, toks, ntok, "label", &label, &labellen) != 0){
    if (cfg.def_label) { label = cfg.def_label; labellen = (int)strlen(cfg.def_label); }
    else { const char *nak = "{\"ok\":false,\"err\":\"no_label\"}"; send_json(fd,&peer,nak); close(fd); return 0; }
  }
  (void)json_get_int((char*)plain, toks, ntok, "ttl", &ttl_req);
  if (json_get_str((char*)plain, toks, ntok, "token", &token, &tokenlen) != 0){
    const char *nak = "{\"ok\":false,\"err\":\"no_token\"}";
    send_json(fd,&peer,nak); close(fd); return 0;
  }
  if (json_get_str((char*)plain, toks, ntok, "key_b64", &key_b64, &keyb64len) != 0){
    const char *nak = "{\"ok\":false,\"err\":\"no_key\"}";
    send_json(fd,&peer,nak); close(fd); return 0;
  }

  if (now_sec() > expires){
    const char *nak = "{\"ok\":false,\"err\":\"expired\"}";
    send_json(fd,&peer,nak); close(fd); return 0;
  }
  if (tokenlen <= 0 || tokenlen != (int)strlen(token_b32) ||
      strncmp(token, token_b32, (size_t)tokenlen) != 0){
    const char *nak = "{\"ok\":false,\"err\":\"bad_token\"}";
    send_json(fd,&peer,nak); close(fd); return 0;
  }

  unsigned char key32[32]; size_t keyout=0;
  if (sodium_base642bin(key32, sizeof(key32),
        key_b64, (size_t)keyb64len, NULL, &keyout, NULL,
        sodium_base64_VARIANT_ORIGINAL) != 0 || keyout != 32){
    const char *nak = "{\"ok\":false,\"err\":\"bad_key_b64\"}";
    send_json(fd,&peer,nak); close(fd); sodium_memzero(key32,sizeof(key32)); return 0;
  }

  int ttl = ttl_req; if (ttl <= 0 || ttl > cfg.ttl_max) ttl = cfg.ttl_max;

  char labelz[256]; if ((size_t)labellen >= sizeof(labelz)) labellen = (int)sizeof(labelz)-1;
  memcpy(labelz, label, (size_t)labellen); labelz[labellen] = '\0';

  key_serial_t kid = add_key_to_keyring(labelz, (size_t)labellen, key32, ttl, cfg.link_user);
  
  sodium_memzero(key32, sizeof(key32));
  sodium_memzero(plain, sizeof(plain));

  char ack[256];
  snprintf(ack, sizeof(ack), "{\"ok\":true,\"keyid\":%d,\"ttl\":%d}", kid, ttl);
  send_json(fd, &peer, ack);

  close(fd);
  return 0;
}
