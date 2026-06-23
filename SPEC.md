# SPEC — ephrun

Minimal specification of the system as it exists today. Descriptive, not aspirational.

---

## Purpose

Encrypted ELF distribution and execution for untrusted Linux hosts (rented VMs, cloud hosts, containers, etc.). The host may have root over the workload and may snapshot disk. On the normal path, the plaintext binary is decrypted into a `memfd` and `fexecve`-d; it does not land on a filesystem path. The `/dev/shm` fallback is an acknowledged exception and is disclosed in the threat model below.

Status: functional and tested on Linux.

---

## Threat model

**In scope (what this defends against):**
- Host reads disk arbitrarily — running, stopped, snapshotted — for the encrypted-ELF file at rest. On the memfd path, plaintext is never written to a filesystem path; the `/dev/shm` fallback is a known exception.
- Host reads container/VM filesystem images at rest.
- Host reads UDP packets in transit (sealed-box auth + secrecy).
- Casual (non-active) memory inspection.
- Stolen capsule files brute-forced offline against memorable passwords (KCAP3 / KCAP2 Argon2id raises the cost; KCAP1 SHA256-only is brute-forceable on GPUs).

**Acknowledged gap — `/dev/shm` fallback (D-16):**
When `memfd_create` is unavailable, or the initial `fexecve` returns `ETXTBSY` (a known kernel-version quirk on some hosts), the plaintext binary is briefly written to `/dev/shm/elfdec-<pid>` (tmpfs) and the workload is launched from that fd. **In the current code:**
- The fallback triggers **only** when `fexecve` fails with `errno == ETXTBSY`. Any other failure (`ENOEXEC`, `EACCES`, etc.) is fatal and does **not** write plaintext to `/dev/shm`.
- The fallback path opens a read-only fd to the tmpfs file, closes the writer, **`unlink()`s the path**, and then `execveat(rofd, "", argv, envp, AT_EMPTY_PATH)`. The plaintext path is no longer reachable on the filesystem when the workload runs; the file inode persists only inside the running process's open-fds.
- On a fallback exec **failure**, the inode is wiped (random bytes via `/proc/self/fd/N`) and the fd is closed before the process exits.

Existing mitigations:
- `O_EXCL` open (no symlink race) on the brief tmpfs creation.
- File mode 0700 (owner only) during the brief window before unlink.

This narrows the `/dev/shm` window to the copy-and-unlink phase (microseconds on a typical host). The "plaintext never touches a *named* path on disk after exec begins" property now holds on both the memfd path and the ETXTBSY fallback path. Active memory forensics on the running process is still in scope (see "Out of scope" below); only the on-disk-path window is closed.

**Out of scope (acknowledged gaps):**
- Active memory forensics (ptrace, `/proc/PID/mem`, gdb attach, live RAM dump).
- Hardware-rooted attestation (no TPM/SGX/Nitro dependency).
- Side channels (timing, cache, power).
- Supply chain compromise of libsodium, glibc, or the kernel.
- Cross-architecture portability beyond x86_64 / arm64 Linux.
- DoS against `keypushd` (no rate limiting; one-shot bootstrap window mitigates).

The bar this raises: from *"copy a file"* to *"live memory forensics on a moving target."* Not bulletproof on hardware you don't own, but materially harder than plaintext.

---

## Components

| Tool | Role | Platform | Source |
|---|---|---|---|
| `genkey` | Generate X25519 keypair (`pub.bin` + `priv.bin`) | any | `ephrun/genkey.c` |
| `elfenc_pack` | Encrypt ELF → `.elfenc` (sealed box, recipient `pub.bin`) | any | `ephrun/elfenc_pack.c` |
| `kcap_pack` | Wrap `priv.bin` with a code → KCAP3 capsule | any | `ephrun/kcap_pack.c` |
| `kcap_unpack` | Unwrap KCAP1/KCAP2/KCAP3 → priv key (cross-platform CLI) | any | `ephrun/kcap_unpack.c` |
| `elfdec-run` | Decrypt `.elfenc` in memory, `fexecve` via `memfd` | Linux | `ephrun/elfdec-run.c` |
| `keypushd` | UDP daemon: receive sealed-box raw priv key into kernel keyring | Linux | `keypush/keypushd.c` |
| `keypush_send` | UDP sender for `keypushd` | Linux + macOS | `keypush/keypush_send.c` |

Header-only library: `ephrun/libexec_key.h` — capsule unwrap + keyring lookup, intended for integration into other tools.

Shared header: `ephrun/kcap.h` — capsule struct, endian helpers, KCAP3 (Argon2id, params in header) + KCAP2 (Argon2id, fixed params, read-only) + KCAP1 (legacy SHA256, read-only) KDFs, plus D-15 receiver param floor/ceiling enforcement.

---

## Data flow

```
─── Builder (trusted) ────────────────────────────────────────────────
   genkey                                  → pub.bin, priv.bin
   elfenc_pack pub.bin myapp myapp.elfenc  → myapp.elfenc       (encrypted ELF)
   kcap_pack --code CODE --in priv.bin     → capsule.bin        (KCAP3 wrapper)

─── Deploy ───────────────────────────────────────────────────────────
   myapp.elfenc + capsule.bin → target host
   priv.bin stays on builder; never deployed

─── Target (untrusted) ───────────────────────────────────────────────
   ELFDEC_CODE="CODE" elfdec-run myapp.elfenc
       1. Find capsule (keyring or ELFDEC_KEYPATH)
       2. Argon2id(code, salt) → K
       3. AEAD-open capsule → priv key (mlocked)
       4. crypto_box_seal_open on .elfenc body
       5. Write plaintext to memfd, seal it, fexecve
```

Alternative key sourcing for the priv key (no capsule): keyring (label or numeric ID) or `ELFDEC_KEYPATH` directory containing `priv.bin`.

---

## Wire formats

### ELFENC1 — encrypted-binary file

```
offset  size  field
   0      8   magic       "ELFENC1\0"
   8      8   clen        uint64 little-endian, ciphertext length
  16    clen  ciphertext  crypto_box_seal(plaintext_elf, pub) [libsodium]
```

`crypto_box_seal` = X25519 ephemeral + XSalsa20-Poly1305. Recipient identity is `pub.bin`; sender is anonymous (ephemeral).

### KCAP3 — current capsule format (D-13)

```
offset  size  field
   0      4   magic        "KCAP" (family preamble)
   4      1   version      0x01
   5      1   project_id   0x01
   6      2   flags        ALL bits MUST be 0 in v1; readers reject any non-zero
   8     16   salt         Argon2id salt (random)
  24      4   time_cost    uint32 LE  (Argon2id T)
  28      4   mem_cost     uint32 LE in KB  (Argon2id M)
  32      4   parallelism  uint32 LE  (Argon2id P)
  36     24   nonce        XChaCha20 nonce (random)
  60      4   ct_len       uint32 LE
  64    ct_len  ct         XChaCha20-Poly1305-IETF(priv[32], K, nonce,
                            ad = bytes 0..63 inclusive — full 64-byte header)
```

KDF: `K = Argon2id(code, salt; T=time_cost, M=mem_cost, P=parallelism, alg=ARGON2ID13)` → 32 bytes. Default packer params: T=3, M=65536 KB, P=1.

D-15 receiver-side parameter policy enforced **before** the Argon2id call: floor `T≥3, M≥64 MiB, P≥1`; ceiling `T≤10, M≤4 GiB, P≤16`. Out-of-policy capsules are rejected without invoking the KDF — defends against malicious packers submitting weak parameters.

AAD covers the full 64-byte header, including the nonce. Wider AAD coverage is strictly more conservative.

### KCAP2 — Argon2id, fixed params (read-only)

Same family-disjoint magic `"KCAP2\0"` shape:

```
   0      7   magic       "KCAP2\0"
   7      1   _pad        0x00
   8      8   t0          uint64 LE, creation unix time
  16      4   ttl         uint32 LE, seconds (0 = no expiry)
  20     16   salt        Argon2id salt
  36     24   nonce       XChaCha20 nonce
  60      4   ct_len      uint32 LE
  64    ct_len  ct        XChaCha20-Poly1305-IETF(priv[32], K, nonce, ad=∅)
```

KDF: `K = Argon2id(code, salt; T=3, M=64 MiB, P=1, alg=ARGON2ID13)` — fixed at compile time; tuning was a wire-format break, which is exactly the problem KCAP3 solved by moving params into the header.

`ttl` enforcement: KCAP2 carried per-capsule TTL; D-13 retired this, and `kcap_pack --ttl` is deprecated with a warning.

A JSON variant with base64 fields (`"v":2`) was supported for debug deployments; deprecated.

### KCAP1 — legacy capsule format (read-only)

Same struct shape with magic `"KCAP1\0"`. KDF differs:

```
K = SHA256("elfdec-kcap" || salt || SHA256(code))
```

Single-pass SHA256 — brute-forceable on GPUs against memorable passwords. Kept readable so already-deployed KCAP1 capsules continue to work; rotate by re-running `kcap_pack` against the original `priv.bin` to produce a KCAP3.

`kcap_pack` writes **only KCAP3**. `elfdec-run` and `libexec_key.h` dispatch by the family magic and read all three (KCAP3 / KCAP2 / KCAP1).

---

## Key sourcing tiers (elfdec-run)

Priority order. First success wins; subsequent tiers are skipped.

| # | Trigger | Source |
|---|---|---|
| 1 | `ELFDEC_CODE` set | KCAP3 / KCAP2 / KCAP1 capsule from kernel keyring (`elfdec_caps:<label>`), then `$ELFDEC_KEYPATH/capsule.bin`, then `$ELFDEC_KEYPATH/capsule.json` (legacy) |
| 2 | `ELFDEC_KEYID` set | Raw priv key by numeric keyring ID |
| 3 | `ELFDEC_LABEL` set | Raw priv key by keyring search `elfdec:<label>` (`@s` then `@u`) |
| 4 | always | `$ELFDEC_KEYPATH/priv.bin`, then `~/.elfenc/priv.bin` |

If `ELFDEC_LABEL` is unset, the canonical path of the `.elfenc` file is used as the label for tier 3.

The public key is derived at runtime via `crypto_scalarmult_base(priv)` — `pub.bin` is not needed at run time.

---

## Crypto primitives

| Use | Algorithm |
|---|---|
| ELF body encryption | X25519 + XSalsa20-Poly1305 sealed box (`crypto_box_seal`) |
| Capsule AEAD | XChaCha20-Poly1305-IETF |
| Capsule KDF (KCAP3, current) | Argon2id, params in header (default T=3, M=64 MiB, P=1; D-15 floor/ceiling enforced) |
| Capsule KDF (KCAP2, read-only) | Argon2id, fixed T=3, M=64 MiB, P=1 |
| Capsule KDF (KCAP1, read-only) | SHA256-based, single-pass |
| Random | `randombytes_buf` (libsodium → kernel CSPRNG) |
| Memory hygiene | `sodium_memzero` on all sensitive buffers; `sodium_mlock` on plaintext + ciphertext heap buffers (D-19) and on `sk` for capsule sourcing only (raw keyring / file paths do not mlock `sk`) |

All primitives are libsodium-provided. No custom crypto.

---

## Execution model (`elfdec-run`)

0. **Pre-init hardening (D-19, runs first thing in `main`, before `sodium_init`):**
   - `prctl(PR_SET_DUMPABLE, 0)` + `prctl(PR_SET_NO_NEW_PRIVS, 1)` — covers the entire unwrap window so a SIGSEGV during decrypt cannot core-dump key material.
   - `unsetenv` over `LOADER_SCRUB_ENV[]` (LD_PRELOAD / LD_AUDIT / DYLD_* / BASH_ENV / NODE_OPTIONS / interpreter-injection family — see `elfdec-run.c:LOADER_SCRUB_ENV`) so children we fork+exec don't inherit them and our own `getenv` calls don't see hostile values.
1. **Tracer check (D-18, defense-in-depth):** read `/proc/self/status`; if `TracerPid != 0` abort before any sensitive work. `ELFDEC_ALLOW_TRACE=1` bypasses the check (dev escape hatch only; the var is itself in the D-17 scrub list). Not a security claim — raises the bar against casual `gdb -p` / same-uid `strace -p`; defeated by root via `/proc` manipulation or kernel rootkit.
2. Source priv key per the tier table above.
3. Open `.elfenc`, validate `ELFENC1` magic, read `clen`, read ciphertext. `sodium_mlock` on the cipher buffer (D-19, best-effort; non-fatal on RLIMIT_MEMLOCK).
4. `crypto_box_seal_open` → plaintext ELF in heap. `sodium_mlock` on the plaintext buffer (D-19, best-effort).
5. `memfd_create("elfdec", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC)`.
6. Write plaintext to memfd.
7. `fcntl(F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)`.
8. `fexecve(fd, child_argv, clean_envp)` — `clean_envp` is built per D-17 + D-19, scrubbing every `ELFDEC_*` var the loader consumed AND the loader-tampering family.
9. `sodium_memzero` + `sodium_munlock` on heap plaintext + ciphertext before exec succeeds; `sodium_memzero` on `sk[32]` (no paired `sodium_munlock`). The capsule unwrap paths in `elfdec-run.c` (lines around 349 / 375 / 405) call `sodium_mlock(out_sk, 32)` after a successful KCAP3 / KCAP2 / KCAP1 unwrap, but `sodium_munlock` is never called on `sk`. Raw keyring (`ELFDEC_KEYID` / `ELFDEC_LABEL`) and file-path (`ELFDEC_KEYPATH`) sourcing modes do **not** mlock `sk` at all — they read directly into the stack `sk[32]` and only `sodium_memzero` it. Treat the mlock as best-effort defense-in-depth on capsule paths only, not a tracked invariant.

**Fallback (D-16, hardened):** if `memfd_create` fails, OR if `fexecve` returns `errno == ETXTBSY`, fall back to `/dev/shm/elfdec-<pid>` opened with `O_EXCL` (TOCTOU mitigation). Any other `fexecve` failure is fatal — no plaintext is written to `/dev/shm`. The fallback path opens a read-only fd, closes the writer, unlinks the path, and uses `execveat(rofd, "", argv, envp, AT_EMPTY_PATH)` (Linux ≥ 3.19) so the workload runs from an unreachable inode. On fallback exec failure, the inode is wiped via `/proc/self/fd/N` and the fd is closed before exit.

**Known fragility:** `fexecve` from a writable memfd can return `ETXTBSY` on some kernels. That is the only failure mode that triggers the `/dev/shm` fallback — every other errno is a hard fail.

**Env hygiene (D-17 + D-19):** `elfdec-run` builds a clean `envp` excluding (a) the ephrun-internal vars `ELFDEC_CODE`, `ELFDEC_KEYID`, `ELFDEC_LABEL`, `ELFDEC_KEYPATH`, `ELFDEC_CAP`, `ELFDEC_ALLOW_TRACE` (D-17), and (b) the loader-tampering family `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, `LD_PROFILE`, `GCONV_PATH`, `HOSTALIASES`, `LOCPATH`, `NLSPATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `BASH_ENV`, `ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `_JAVA_OPTIONS`, `JAVA_TOOL_OPTIONS`, `CDPATH`, `GLOBIGNORE` (D-19). The workload and any process it spawns do not see these variables in their environment.

---

## Build

`make` from repo root invokes `ephrun/Makefile` and `keypush/Makefile`. `STATIC=1` for static linking (deployment to remote machines without matching libsodium).

Cross-platform: `genkey`, `elfenc_pack`, `kcap_pack`, `kcap_unpack`, `kcap_kdf_test` (Linux + macOS).
Linux-only: `elfdec-run`, `keypushd`, `test_key`, `keyring_selftest`, `keyring_crypto_test`.

`make -C ephrun check` runs the cross-platform `kcap_kdf_test` (KCAP3 round-trip + fixture decrypt + AAD-mutation rejection + D-15 param floor/ceiling rejection; KCAP2 fixture decrypt; KCAP1 fixture decrypt; wrong-code rejection; Argon2id timing sanity; non-`KCAP` magic rejection).

`bash test.sh` runs the full Linux end-to-end suite (46 tests covering build + all 4 key modes + capsule-in-keyring + KCAP3 magic/AAD/policy + D-16 fallback (ETXTBSY-only, unlink-before-execveat, env-scrub on fallback path) + D-17 env scrub + D-18 ptrace defense + D-19 LD_PRELOAD strip from workload envp (AC-03-08) + negative tests).

---

## Status

Functional and tested on Linux.

**Known limitations:**
- Linux-only target. macOS / Windows / *BSD execution not supported.
- KCAP2 capsule KDF params (Argon2id T=3, M=64 MiB) are hardcoded — tuning is a wire-format break (KCAP3 fixes this by moving params into the header).
- KCAP2 AEAD does not bind KDF params via AAD — fine while params are hardcoded, must change before per-capsule params land.
- `keypushd` has no rate limiting on UDP — relies on one-shot token + short bootstrap window.
- Container kernel keyring access varies by host config; `add_keyring*.sh` scripts try multiple permission masks but cannot guarantee access in restrictive containers.

**Not supported by design:** see threat model "Out of scope."
