# SECURITY — ephrun

This document is the **integrated** threat model. It is not a re-statement
of every D-N. The per-decision reasoning lives in `DECISIONS.md`; the
testable invariants live in `ACCEPTANCE_CRITERIA.md`. This file is the
operator-facing distillation: what the system protects against today, what
it does not, and where the boundaries are drawn.

Single-author project. No compliance angle. No SLA. The bar this raises
is "stolen file at rest" → "live memory forensics on a moving target on a
host you don't own." That is a real, useful bar — and it is not
bulletproof.

---

## 1. Threat Model — scope

ephrun defends artifacts and key material **at rest** and protects the
running process against *passive* host inspection. It does **not** defend
against an active adversary with live root on the execution host. The
boundary is drawn deliberately and is stated explicitly below.

### 1.1 The adversary

The adversary is the **untrusted host operator** of a rented or cloud-hosted
VM/container. They have:

- Root over the workload's user namespace.
- Disk read access to anything written to a filesystem path, including
  while the VM is running, paused, or snapshotted.
- The ability to read UDP packets in transit on the host network.
- The ability to inspect the running process *passively* — read
  `environ`, `cmdline`, `status`, the file table.
- The ability to brute-force any encrypted artifact they capture,
  offline, at their leisure.

The system does **not** aim to defend against the case where this
adversary actively memory-forensics the running `elfdec-run` or workload
— `gdb -p`, `/proc/<pid>/mem`, kernel rootkits, live patching, ptrace
attach mid-execution. Those are out of scope and listed in §4.

### 1.2 What is in scope

- Encrypted ELFs at rest on the target's disk.
- Capsule files at rest on the target's disk.
- VM snapshots / image extraction that captures all of the above.
- UDP transit of priv keys over `keypushd` (sealed-box authenticated
  + confidential).
- Casual `gdb -p` / same-uid `strace -p` against `elfdec-run` startup
  (D-18 — defense-in-depth, not a guarantee).
- Plaintext leakage to swap during the decrypt-write window (D-19
  mlock).
- Plaintext leakage to core dumps (D-19 early `PR_SET_DUMPABLE=0`).
- Loader-tampering env vars (`LD_PRELOAD`, `LD_AUDIT`, etc.) leaking to
  workload children (D-19).
- ephrun-specific env vars (`ELFDEC_CODE`, `ELFDEC_KEYID`, ...)
  leaking to the workload (D-17).
- Plaintext binary persisting on a filesystem path while the workload
  is running — closed on the memfd path (D-2) and on the
  `/dev/shm` ETXTBSY fallback path (D-16).

### 1.3 What is out of scope

- Active memory forensics on a running `elfdec-run` or workload by
  hostile root. There is no defense against `/proc/<pid>/mem`
  read by root; the entire address space — plaintext binary, decrypted
  priv key, derived AEAD key, passphrase residue — is readable.
- Hardware attestation. No TPM, SGX, SEV, or Nitro dependency.
- Side channels (timing, cache, power, EM).
- Supply-chain compromise of libsodium, glibc, the kernel, or the
  toolchain that built `elfdec-run`.
- Cross-architecture beyond x86_64 / arm64 Linux. macOS / Windows /
  *BSD are not supported as execution targets (the cross-platform
  build targets cover `genkey`, `elfenc_pack`, `kcap_pack` only).
- DoS against `keypushd`. No rate limiting. The one-shot bootstrap
  window is the mitigation.
- Operator passphrase entropy. Argon2id raises the cost of brute force
  per guess; it does not save weak passphrases. A 4-character code is
  brute-forceable in seconds *regardless* of the KDF.

---

## 2. Architecture Layer View

Four layers. Each has its own crypto and its own threat assumption.
Citations point to D-N for the load-bearing decision.

**Layer 1 — ELFENC sealed box (D-3).** ELF body is encrypted with
`crypto_box_seal` (X25519 ephemeral + XSalsa20-Poly1305). Recipient
identity is `pub.bin`; sender is anonymous (ephemeral keypair per
encryption). *Threat assumption:* the recipient priv key is held only
by parties authorized to decrypt the workload. Two encryptions of the
same plaintext produce different ciphertexts (semantic security per
encryption). **Not forward secrecy** — disclosure of the long-term
recipient priv key decrypts every past `.elfenc` file.

**Layer 2 — Linux kernel keyring (D-4).** Optional priv-key transport.
`keypushd` accepts a sealed-box-wrapped priv key over UDP and stows
the raw priv into the kernel keyring; `elfdec-run` searches the keyring
by label or numeric ID before falling back to `$ELFDEC_KEYPATH`.
*Threat assumption:* the keyring is process-uid-scoped and survives
only as long as the keyring session does. A reboot wipes it. Root on
the host can read any keyring; this is acknowledged, not defended.

**Layer 3 — KCAP3 capsule (D-1, D-13, D-15).** Argon2id-derived
(T=3, M=64 MiB, P=1 default) XChaCha20-Poly1305-IETF wrap of the priv
key. AAD covers the full 64-byte header including nonce (D-13).
Receiver-side parameter floor and ceiling (D-15) are enforced *before*
Argon2id is invoked, defending against malicious packers. *Threat
assumption:* the operator passphrase has enough entropy that Argon2id
at the configured cost is infeasible to brute-force at the attacker's
budget. This is an operator responsibility, not a system property.

**Layer 4 — `memfd_create` + `fexecve` / `execveat` fallback (D-2, D-16,
D-17, D-18, D-19).** Decrypt to anonymous `memfd` sealed with
`F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL`, then
`fexecve`. ETXTBSY fallback narrows plaintext-on-disk to a brief
copy-and-unlink window (D-16, AC-03-04, AC-03-05). Any other `fexecve`
errno is fatal; no plaintext touches `/dev/shm`. Ptrace defense (D-18)
and env-var hygiene (D-17, D-19) layer on top. *Threat assumption:* the
kernel is honest about what `memfd_create`, `fexecve`, and `execveat`
mean — i.e., a kernel rootkit that lies about filesystem visibility
defeats the whole layer.

---

## 3. Security Properties — checkbox matrix

Concrete, not aspirational. Every entry is testable today (cite the AC).

### 3.1 What is PROVIDED

```
[X] ELF body confidential at rest                   (D-3, AC-01-A scope: ELFENC1)
[X] ELF body integrity at rest under recipient priv (D-3, sealed-box AEAD)
[X] Capsule confidential at rest                    (D-13, AC-01-B-02)
[X] Capsule integrity (full-header AAD)             (D-13, AC-01-B-04)
[X] Capsule KDF cost ≥ Argon2id T=3 M=64MiB         (D-1, D-15, AC-01-B-07)
[X] Receiver-side KDF parameter floor enforcement   (D-15, AC-01-B-07)
[X] Receiver-side KDF parameter ceiling (DoS)       (D-15, AC-01-B-08)
[X] UDP keypushd transport authenticated+confidential
                                                    (D-7, sealed-box on UDP;
                                                     design-asserted, no AC)
[X] No plaintext binary on persistent filesystem
    after exec begins (memfd path)                  (D-2, AC-03-03)
[X] No plaintext binary on persistent filesystem
    after exec begins (ETXTBSY fallback path)       (D-16, AC-03-04, AC-03-05)
[X] Plaintext wiped on fallback exec failure        (D-16, AC-03-04(b))
[X] No plaintext binary in process core dump         (D-19 early PR_SET_DUMPABLE,
                                                     AC-03-06)
[X] mlock attempted on plaintext + ciphertext heap
    buffers (narrows swap-leak window during unwrap)  (D-19; non-fatal
                                                       on RLIMIT_MEMLOCK,
                                                       not a guarantee
                                                       — see §3.2)
[X] No ELFDEC_* env var leaks to workload           (D-17, AC-03-07)
[X] No loader-hijack env var leaks to workload      (D-19, AC-03-08)
[X] No ELFDEC_ALLOW_TRACE leaks to workload         (D-18 + D-17, AC-03-07)
[X] Refuses to start under casual ptrace tracer     (D-18, baseline check)
[X] No NEW_PRIVS during workload                    (PR_SET_NO_NEW_PRIVS,
                                                     SPEC §execution-model;
                                                     design-asserted, no AC)
[X] No passphrase / priv key in stdout/stderr/logs  (AC-03-02)
[X] No passphrase / priv key in `strings` of any
    deployed file                                   (AC-03-01)
[X] Two encryptions of same plaintext → different
    ciphertext                                       (D-3 ephemeral sender;
                                                     primitive property, no AC)
[X] Wrong passphrase → AEAD failure, no plaintext   (AC-01-B-05)
```

### 3.2 What is NOT PROVIDED

```
[ ] Forward secrecy across recipient priv key disclosure
    (D-3 sealed-box has only sender ephemerality)
[ ] Defense against root with /proc/<pid>/mem        (out of scope, §1.3)
[ ] Defense against ptrace attach AFTER startup check (D-18 limits)
[ ] Defense against kernel rootkit lying about TracerPid, memfd,
    or fexecve semantics                              (D-18 limits, structural)
[ ] Defense against weak passphrases (Argon2id raises per-guess cost,
    not the floor of operator entropy)
[ ] Online revocation (no capability check today)
[ ] Hardware attestation of executing host           (out of scope, §1.3)
[ ] Active memory forensics resistance               (out of scope, §1.3)
[ ] Side-channel resistance                          (out of scope, §1.3)
[ ] mlock guarantees on hardened distros where RLIMIT_MEMLOCK = 0
    (D-19: failure is non-fatal; defense-in-depth, not a hard requirement)
[~] OOM-on-Argon2id clean-exit guarantee              (AC-03-09: dual-case
                                                       via systemd-run --user
                                                       --scope — positive at
                                                       MemoryMax=96M must
                                                       succeed, negative at
                                                       MemoryMax=24M must
                                                       fail with ENOMEM
                                                       not SIGKILL.
                                                       kcap3_unpack sets
                                                       errno=ENOMEM on
                                                       crypto_pwhash
                                                       allocation failure
                                                       so the path is
                                                       distinguishable
                                                       from EACCES wrong-
                                                       code.)
[ ] Plaintext residence in RAM during workload execution
    (the workload IS the plaintext binary, in memory, by definition)
[ ] keypushd rate-limiting / DoS resistance          (D-7, out of scope)
[ ] Cross-architecture beyond x86_64 / arm64 Linux execution
[ ] macOS / Windows / *BSD execution
```

---

## 4. Known Non-Properties — explicit list

The following are **NOT** properties of ephrun and are listed here so
no operator misreads §3 by omission.

1. **A hostile root with `/proc/<pid>/mem` defeats every layer of
   ephrun, full stop.** The decrypted priv key, the Argon2id-derived
   AEAD key, the plaintext binary, the passphrase residue between
   `getenv` and `sodium_memzero` — all of it is in the
   `elfdec-run` address space and readable to root. D-19 mlock and
   `PR_SET_DUMPABLE=0` reduce *passive* leakage (swap, core dumps);
   neither stops a root that actively reads memory.

2. **`/dev/shm` fallback exposes plaintext during the
   copy-and-unlink window.** D-16 narrows this to microseconds and
   to the `ETXTBSY`-only path; the file is created with `O_EXCL`, mode
   0700, and `unlink()`ed before `execveat(AT_EMPTY_PATH)`. After
   `unlink()` the inode is reachable only via the running process's open
   fd. **However:** during the brief tmpfs window, a same-uid or root
   reader on the host *can* read the plaintext if they win the race.
   The window is not zero. Operators in environments where the
   `ETXTBSY` fallback is reachable (kernels 3.19 ≤ x < 6.x with the
   memfd-fexecve quirk) should treat that brief window as a known
   exposure.

3. **Passphrase entropy is the operator's problem.** Argon2id at
   T=3, M=64 MiB raises the cost per guess to roughly 100 ms on a
   modern CPU and several GiB-seconds of RAM-time. This makes a
   GPU farm useless against memorable passwords *of sufficient
   entropy*. It does **not** make a 4-character code safe — that's
   ~10⁵ guesses, around a few CPU-hours total. The KDF cannot
   compensate for low-entropy inputs.

4. **Forward secrecy is not provided.** Sealed boxes (D-3) have an
   ephemeral *sender* key but a long-term *recipient* key. If the
   recipient priv ever leaks — captured from the keyring on a
   compromised host, brute-forced from a stolen capsule, leaked from
   the builder's `priv.bin` — every past `.elfenc` encrypted to that
   pubkey becomes decryptable. Mitigation: rotate the recipient
   keypair when there's any suspicion of compromise (§7).

5. **Supply-chain compromise is out of scope.** A backdoored
   libsodium, a backdoored glibc, a malicious `binfmt_misc` handler,
   or a backdoored `elfdec-run` itself defeat the system entirely.
   `STATIC=1` linkage reduces the libsodium swap-out attack surface;
   it does nothing against a backdoor in the libsodium source you
   compiled.

6. **Physical access to the running process defeats the system.**
   This includes: the hypervisor host taking a memory snapshot of a
   running guest, a cold-boot attack, JTAG / SMM access, a colocated
   workload on the same NUMA node performing Rowhammer or
   speculative-execution side channels. None of these are defended
   against; all of them are realistic for "rented hardware you don't
   own."

7. **TracerPid check only; `PTRACE_TRACEME` is not used because it
   mutates signal-delivery semantics (D-18).** The check is one-shot:
   tracers attaching after startup, tampered `/proc/self/status`, and
   kernel rootkits all defeat it. D-18 is bar-raising against
   opportunistic same-uid `gdb -p` / `strace -p`, not a guarantee.

8. **D-19 LD_PRELOAD scrub protects children and the workload, not
   `elfdec-run` itself.** glibc has already honored `LD_PRELOAD` by the
   time `main()` runs; the scrub does not retroactively unload an
   already-loaded `.so`. `STATIC=1` is the answer for hardening
   `elfdec-run`'s own image (D-19).

9. **The workload runs with the operator's full privileges.**
   `elfdec-run` does not sandbox the workload (no seccomp, no
   namespace, no capability drop beyond `PR_SET_NO_NEW_PRIVS`).
   A malicious or vulnerable workload has whatever the launching
   shell had. Sandboxing is a deployer concern, not a property of
   ephrun.

10. **There is no rate limit or anti-replay on `keypushd`.** The
    one-shot bootstrap-window pattern (D-7) is the only mitigation:
    open the daemon, push the key, close the daemon. Leaving
    `keypushd` running on a public-IP host is a misuse.

---

## 5. Worked Example — cloud host snapshot mid-execution

**Scenario.** You run a workload on a third-party cloud/container host. You deploy `myapp.elfenc`
+ `capsule.bin` to the container. You run
`ELFDEC_CODE="goodlongpassphrase" elfdec-run myapp.elfenc`. The
workload starts.

While the workload is running, the host operator does the following:

1. Snapshots the VM's persistent disk.
2. Snapshots the running VM's RAM (live migration capture).
3. Reads `/proc/<elfdec-run-pid>/mem` and `/proc/<workload-pid>/mem`
   while the processes are alive.
4. Stops the VM and walks away with everything.

**What the host operator has after step 1 (disk only).**

- `myapp.elfenc` — ELFENC1 ciphertext under your `pub.bin`.
- `capsule.bin` — KCAP3 with `time_cost=3, mem_cost=64MiB,
  parallelism=1`, AAD-bound 64-byte header, XChaCha20-Poly1305-IETF
  wrap of `priv[32]` under `K = Argon2id(passphrase, salt; T, M, P)`.

What they can do offline, at leisure, using their own hardware:

- Brute-force the passphrase against `capsule.bin`. Argon2id at
  T=3 / M=64 MiB / P=1 is roughly ~100 ms / GiB·s per guess on a
  modern CPU; GPUs do not buy meaningful speedup against
  memory-hard KDFs at this memlimit. A 60-bit-entropy passphrase
  (~10¹⁸ guesses) is computationally infeasible at any realistic
  budget. A 4-word diceware passphrase (~52 bits) is borderline.
  A 4-character code (~24 bits) cracks in CPU-hours. **The
  passphrase decides the at-rest game; the KDF only sets the
  per-guess cost.**

- If the passphrase cracks: extract `priv[32]`, then
  `crypto_box_seal_open(myapp.elfenc, priv)` recovers the plaintext
  ELF. Game over for *that pubkey*. Future `.elfenc` files
  encrypted to the same `pub.bin` also decrypt.

- If the passphrase does not crack: ELFENC1 ciphertext is just
  bytes. No metadata in the format. The host knows you ran
  *something*. They do not learn what.

**What step 2 adds (RAM snapshot of the running VM).** The plaintext
ELF is in `elfdec-run`'s heap during the brief
decrypt → write-to-memfd window (D-19 mlocks it, but mlock does not
hide it from the host hypervisor; it only excludes it from swap
*inside* the guest). The decrypted `priv[32]` is in
`elfdec-run`'s mlocked memory until `sodium_munlock` runs. The
plaintext ELF is in the memfd's anonymous-mapped backing pages for
the workload's lifetime — those pages *are* the running workload, by
definition. After the snapshot:

- The host has the workload's full memory image. They have the
  plaintext ELF. They have `priv[32]` if the snapshot caught it
  pre-munlock. They can extract everything.

- D-19 `PR_SET_DUMPABLE=0` runs at startup, so the kernel will not
  produce a core dump from the *guest's* perspective. This is
  irrelevant to the *host's* memory snapshot of the guest VM —
  the guest has no power to hide pages from the hypervisor.

**What step 3 adds (`/proc/<pid>/mem`).** Same story as step 2,
but live and selective. The host can `cat
/proc/<elfdec-run-pid>/mem | strings` and find the priv key, the
passphrase residue, the plaintext ELF — anything in the address
space, regardless of mlock. This is the canonical "defeated by
hostile root" path.

**What the `/dev/shm` window adds (only if reached).** If
`fexecve` returns `ETXTBSY` and the fallback runs, there is a
microsecond-scale window where `/dev/shm/elfdec-<pid>` exists
on tmpfs as a 0700 file before `unlink()` and `execveat()`. A
host root running `inotifywait -m /dev/shm` could capture the
file in that window. After `unlink()`, the workload runs from an
inode with zero filesystem references. The fallback hardening
(D-16) closes the post-exec on-disk gap; it does not close the
microsecond window during copy-and-unlink.

**What the operator should take away.** ephrun on an untrusted
cloud/container host raises the bar from *"copy a file"* (which happens)
to *"do live memory forensics on a moving target, or brute-force a strong
passphrase offline"* (which costs real time and money). It is the right
tool for at-rest protection **only if your passphrase is genuinely
strong**. It is not a defense against a hostile root user who inspects the
running process.

For "I do not trust this host even while my code runs," no
software-only design helps — including this one. Defending a
running process against the host that owns the hardware requires
hardware-attested execution, which ephrun does not provide.

---

## 6. Key Material Lifecycle

Where keys live at each stage. Cite D-N for details; do not re-explain.

**Generation (`genkey`, D-3).** X25519 keypair via libsodium
`crypto_box_keypair`. `pub.bin` and `priv.bin` written to the builder.
`priv.bin` mode is the umask default — operators should `chmod 600`
explicitly. The builder is **trusted**; this document does not defend
the builder.

**Capsule wrap (`kcap_pack`, D-1, D-13).** `priv.bin` is read into a
buffer, `K = Argon2id(passphrase, salt; T=3, M=64MiB, P=1)` derives
the wrap key, `XChaCha20-Poly1305-IETF.Seal(K, nonce, priv[32], AAD =
header[0..63])` produces the ciphertext. `K`, the passphrase, and the
plaintext `priv[32]` are wiped via `sodium_memzero` before scope
exit (AC-01-G-03). `kcap_pack` writes only KCAP3 (AC-01-E-03);
KCAP1/KCAP2 are read-only legacy.

**Deployment.** `myapp.elfenc + capsule.bin` go to the target. `priv.bin`
**stays on the builder** — it is never deployed. Capsule may be:
written to a file in `$ELFDEC_KEYPATH`, embedded in the kernel keyring
(`elfdec_caps:<label>`), or pushed via `keypushd` (D-7, transitional).

**Runtime unwrap (`elfdec-run`, D-2, D-17, D-18, D-19).**

1. **Process hardening** runs *first* (D-19), in this order, all
   before `sodium_init`: (a) `prctl(PR_SET_DUMPABLE, 0)` and
   `prctl(PR_SET_NO_NEW_PRIVS, 1)` so a SIGSEGV during unwrap does
   not produce a core dump containing key material; (b) `unsetenv`
   of the D-19 deny-list (`LD_PRELOAD`, `LD_LIBRARY_PATH`, ...) on
   `elfdec-run`'s own environ.

2. **Ptrace check** (D-18): read `/proc/self/status`; abort if
   `TracerPid != 0` unless `ELFDEC_ALLOW_TRACE=1`. The bypass var is
   itself in the D-17 scrub list.

3. **Source the priv key** by D-4 four-tier priority. KCAP3/KCAP2/KCAP1
   capsules are unwrapped by passing through the family-magic
   dispatch (D-13). KCAP3 enforces D-15 parameter floor + ceiling
   *before* Argon2id runs.

4. **mlock** (D-19) the plaintext ELF and ciphertext heap buffers.
   Failure is non-fatal (RLIMIT_MEMLOCK on hardened distros);
   defense-in-depth.

5. **Decrypt ELF body** with `crypto_box_seal_open(ciphertext, pub
   derived from priv)`.

6. **Write plaintext to memfd**, seal it (`F_SEAL_*`), then
   `fexecve(memfd, child_argv, clean_envp)`. `clean_envp` is the
   D-17 + D-19 scrub-list-stripped environment.

7. **Wipe** before exec succeeds: heap plaintext + ciphertext via
   `sodium_munlock` (implies memzero); `sk[32]` via `sodium_memzero`
   only (no paired `sodium_munlock`). On capsule sourcing paths,
   `elfdec-run.c` calls `sodium_mlock(out_sk, 32)` after a successful
   KCAP3 / KCAP2 / KCAP1 unwrap (no munlock); raw keyring and file
   paths do not mlock `sk` at all. Defense-in-depth on capsule
   paths only — not a tracked invariant across all four sourcing
   tiers.

8. **Fallback (D-16)**: only on `errno == ETXTBSY`, copy plaintext
   to `/dev/shm/elfdec-<pid>` (`O_EXCL`, 0700) → open RO fd →
   close writer → `unlink(path)` → `execveat(rofd, "", argv,
   envp, AT_EMPTY_PATH)`. On exec failure, wipe the inode via
   `/proc/self/fd/N` and exit non-zero.

**Post-exec.** The workload's address space *is* the plaintext binary
plus whatever it allocates. The decrypted priv key has been wiped
(step 7). The capsule remains on disk under the original passphrase
wrap. The operator's `ELFDEC_CODE` env var is **not** in the
workload's environ (D-17, AC-03-07).

**Compromise indicators.**

- Recipient `priv.bin` ever observed in plaintext on a target's
  filesystem → assume compromise, rotate (§7).
- Unauthorized capsule with the operator's `pub.bin` as recipient,
  decryptable with the operator's passphrase, found in the wild →
  someone is mid-exfiltration.
- `keypushd` connection from an unexpected source → rotate the
  bootstrap token; assume the priv key in flight is captured.

---

## 7. Compromise Response

- **Recipient priv compromise.** Regenerate the keypair with
  `genkey`. Re-pack every `.elfenc` with the new `pub.bin`. Verify
  the new pubkey fingerprint **out of band** (non-ephrun channel
  — Signal, voice, in person). Push fresh capsules. The compromised
  priv decrypts every prior `.elfenc` it ever could; only **prior**
  artifacts are at risk, and *only if the attacker has captured the
  ciphertext*.
- **Capsule passphrase compromise.** Re-pack the capsule (`kcap_pack`)
  against the same `priv.bin` with a **different, stronger**
  passphrase. The old capsule remains decryptable by the old
  passphrase but the priv key it wraps is unchanged — so this
  helps **only if the attacker has the old capsule but not the
  passphrase yet**. If the attacker has both, they have the priv;
  treat as priv compromise above.
- **Suspected `/dev/shm` window leak.** Rotate the priv keypair
  (priv compromise above) and stop running on hosts where
  `ETXTBSY` is reached. Track in your deployment notes which
  kernels exhibit the quirk.
- **`keypushd` token replay.** Stop the daemon. Generate a new
  bootstrap token. The compromised priv key is now in the
  attacker's hands; rotate.
- **Builder host compromise.** Treat as recipient priv compromise.

---

## 8. Operational Guardrails

`DECISIONS.md` is the **authoritative source** for per-decision
reasoning. This document is the integrated view; it cites D-N and
trusts the reader to follow the citation when context is needed.

**Load-bearing decisions.**

- D-1 (Argon2id KDF) — capsule per-guess cost.
- D-2 (memfd over /dev/shm) — execution path with no on-disk
  plaintext.
- D-3 (X25519 + XSalsa20-Poly1305 sealed box) — ELF body crypto.
- D-4 (four-tier key sourcing) — operational flexibility; each
  tier earns its keep.
- D-13 (KCAP3 wire format) — AAD-bound capsule; supersedes KCAP2.
- D-15 (KCAP3 receiver param floor/ceiling) — defense against
  malicious packers.
- D-16 (`/dev/shm` fallback hardening) — closes the
  named-path-on-disk gap on the ETXTBSY path; explicit kernel
  floor (Linux ≥ 3.19).
- D-17 (`ELFDEC_*` env scrub) — workload does not see ephrun
  control vars.
- D-18 (TracerPid check) — defense-in-depth against casual
  ptrace; not a security claim.
- D-19 (loader env scrub + mlock + early `PR_SET_DUMPABLE`) —
  closes core-dump leakage, narrows swap leakage (best-effort
  mlock, non-fatal on RLIMIT_MEMLOCK), and strips loader-tampering
  vars from workload envp.

**Decisions retired or transitional.**

- D-5 (KCAP1 read-only) — legacy; remove the read path when no
  field deployment needs it.
- D-7 (`keypushd` UDP transport) — transitional; no further investment.

See `ACCEPTANCE_CRITERIA.md` AC-N for the testable invariants.
AC-03 (cross-cutting threat-model invariants) is the canonical
check for the claims in this document.

---

## 9. Reporting

Single-author project. No SLA, no embargo policy, no security mailing
list.

**File an issue at https://github.com/nmicic/ephrun.** Security-
relevant findings get priority over feature requests. If the finding
involves a live deployment in the wild and you'd prefer not to
file in public, the contact email on the operator's GitHub
profile is the right channel; expect reply latency on the order of
days, not hours. Coordinated disclosure is welcome but not required.
The project's tone is "honest about scope" — please match it in
reports.
