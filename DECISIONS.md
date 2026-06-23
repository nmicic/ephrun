# DECISIONS — ephrun

Load-bearing architectural decisions, with **why**.

Each entry: D-N, title, decision, rationale, and alternatives considered.

---

## D-1: Argon2id for capsule KDF (KCAP2)

**Decision:** Use libsodium's `crypto_pwhash` (Argon2id, T=3, M=64 MiB, P=1) to derive the capsule key from the operator code.

**Why:**
- Memory-hard KDF defeats GPU brute force against memorable passwords.
- libsodium ships it; no new dependency.
- Uses a well-reviewed libsodium primitive; ephrun's parameter choice is tuned for this threat model.

**Alternatives considered:**
- scrypt — also memory-hard, but Argon2id is the modern winner of the Password Hashing Competition and what libsodium recommends.
- bcrypt — not memory-hard.
- PBKDF2 — not memory-hard, only marginally better than the SHA256 it replaced.
- Single-pass SHA256 (KCAP1) — what we replaced. GPU-brute-forceable.

---

## D-2: `memfd` over `/dev/shm` for execution

**Decision:** Decrypt plaintext binary into `memfd_create` fd with `MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC`, seal with `F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL`, then `fexecve`. Fall back to `/dev/shm` only if `memfd_create` fails.

**Why:**
- `memfd` lives in anonymous memory; never visible in the filesystem at any path.
- Seals provide kernel-enforced immutability of the executable image after write.
- `fexecve` allows execution by fd directly, no path traversal.
- `/dev/shm` is a real tmpfs file with a path — visible to other processes, racy, requires `O_EXCL` to mitigate symlink/TOCTOU.

**Alternatives considered:**
- Always `/dev/shm` — simpler but worse.
- `ptrace`-injected execution into a parent shell — too fragile, brittle across kernel versions.
- `dlopen` of a position-independent ELF — doesn't run normal binaries.

**Known fragility:** some kernels return `ETXTBSY` when `fexecve`-ing a writable memfd; we catch this, copy to `/dev/shm`, close the writable fd, and retry with `execve`. Documented in `SPEC.md`.

---

## D-3: X25519 + XSalsa20-Poly1305 sealed boxes for ELF body

**Decision:** Encrypt ELF plaintext with `crypto_box_seal` (libsodium): X25519 ephemeral keypair + XSalsa20-Poly1305 AEAD. Recipient identity is `pub.bin`; sender is anonymous.

**Why:**
- Anonymous sender — anyone with the recipient's pubkey can encrypt; only the recipient can decrypt. Matches the deploy model (builder encrypts, target decrypts).
- libsodium primitive — well-audited, well-tested.
- **Semantic security per encryption.** Each `elfenc_pack` run uses a fresh ephemeral sender keypair, so two encryptions of the same plaintext produce different ciphertexts. **NOT forward secrecy** — if the recipient's long-term priv key is later disclosed, all past `.elfenc` files become decryptable. Forward secrecy would require ephemeral keys on *both* ends; sealed-box only has ephemeral on the sender.

**Alternatives considered:**
- AES-GCM with a derived key — requires shared key distribution; we'd be solving the same problem twice.
- Symmetric session key conveyed in the capsule — works, but couples body encryption to the capsule format.

---

## D-4: Four-tier key sourcing priority in `elfdec-run`

**Decision:** `elfdec-run` tries to source the priv key in this order, first success wins:
1. `ELFDEC_CODE` → capsule (keyring or `ELFDEC_KEYPATH`)
2. `ELFDEC_KEYID` → numeric keyring ID
3. `ELFDEC_LABEL` → keyring search `elfdec:<label>`
4. `ELFDEC_KEYPATH` or `~/.elfenc/` → `priv.bin` file

**Why:**
- Each tier serves a distinct deployment posture (capsule deploy, pre-pushed key, label-based dispatch, file-based dev).
- Priority order favors the most-secure-on-target first (capsule never touches plaintext on disk) and falls back gracefully.

**Alternatives considered:**
- One mode only (file-based) — too rigid for deployment scenarios.
- CLI flags instead of env vars — env vars compose better in shell pipelines and binfmt_misc.
- Sourcing on stdin — usable, but env var is consistent with how other crypto tooling does it.

---

## D-5: `KCAP1` retained as read-only

**Decision:** `kcap_pack` writes only KCAP3 (D-13). `elfdec-run` and `libexec_key.h` dispatch by family magic and accept KCAP1 / KCAP2 / KCAP3 on read. `kcap_derive_k` (legacy SHA256 KDF) is preserved in `kcap.h` solely for the KCAP1 read path; the KCAP2 read path uses `kcap_derive_k_v2` (Argon2id with hardcoded params).

**Why:**
- Already-deployed KCAP1 capsules on remote VMs continue to work.
- Migration is "re-run kcap_pack against the original priv.bin" — no ceremony.
- Removing KCAP1 read would force a coordinated rotation across all deployed capsules.

**Alternatives considered:**
- Hard-fail on KCAP1 — simpler code, abrupt break for any extant deployment.
- One-time migration tool — adds complexity, doesn't help if the operator re-runs an old `kcap_pack`.

---

## D-6: No JSON wire format

**Decision:** New capsule formats are binary, not JSON. A JSON capsule variant (`kcap_pack --json`) is preserved for current human-readable / debug use only and will not be extended.

**Why:**
- ~30% size bloat after base64 encoding binary fields.
- JSON parsing in C is bug-prone (we already maintain a micro-parser in `elfdec-run.c`; it's a smell).
- Canonicalizing JSON for AEAD AAD coverage is non-trivial; binary headers AAD trivially.
- Schema flexibility is illusory — each project ends up with a different schema anyway.

**Alternatives considered:**
- All-JSON wire format — tempting for human readability, but every cost above applies.
- CBOR (binary JSON-like) — less ad-hoc than the JSON we have, but still adds a tokenizer dependency without buying anything over a fixed binary header.

---

## D-7: `keypushd` UDP transport

**Decision:** `keypushd` + `keypush_send` provide a UDP transport for pushing keys to a target, using an out-of-band `srv_pk + token` paste to bootstrap.

**Why:**
- Working code that solves the immediate need of getting a key onto a target.

**Known limits:**
- Out-of-band token paste is a manual step that doesn't scale.
- No store-and-forward — receiver must be online when sender pushes.
- No PAKE — sender can't authenticate the receiver beyond the bootstrap window.

---

## D-8: Capsule format is self-contained

**Decision:** ephrun capsules and tools are buildable, deployable, and useful with no external runtime dependency. The capsule is a wire artifact; its definition does not require linking against another project's runtime.

**Why:**
- Avoids one project's instability cascading into another.
- Capsules are wire artifacts; their definition shouldn't require linking against another project's runtime.

**Alternatives considered:**
- Define the capsule format inside a transport project and have ephrun use it — wrong direction; ephrun has the longer-running format need.

---

## D-10: Revocation = short-lived validity window

**Decision:** Capsules/keys carry a validity window (`not_before`, `not_after`). "Revocation" = stop re-issuing; the artifact expires naturally. Clock skew tolerance ±60s.

**Why:**
- No online dependency at exec time → scripts stay fast.
- Failure mode is "artifact expires" not "responder down" — graceful.

**Alternatives considered:**
- **CRL** — target maintains revocation list. Stateful, stale, distribution problem.
- **OCSP query** — target asks issuer at exec time. Online dependency, leaks usage patterns.

---

## D-11: Passphrase-wrap is the canonical key-protection pattern

**Decision:** A long-term audience priv key on the target is wrapped in a passphrase capsule (KCAP3 today per D-13; KCAP1 / KCAP2 also readable for migration). The operator supplies the passphrase via the `ELFDEC_CODE` env var.

**Why:**
- Operator retains control via passphrase.
- No new abstractions needed.

**Alternatives considered:**
- **Always-keyring-only (no passphrase)** — simpler, but loses offline-disk-attack defense (priv lives in keyring across reboots).
- **TPM-bound priv** — strongest, but ties to specific hardware.

---

## D-13: KCAP3 wire format

**Decision:** Capsule format with a family-magic preamble. `kcap_pack` writes KCAP3 by default; `elfdec-run` dispatches KCAP1/KCAP2/KCAP3 by family magic.

```
offset  size  field
   0     4    magic        "KCAP" (family preamble)
   4     1    version      0x01
   5     1    project_id   0x01   (ephrun)
   6     2    flags        ALL bits MUST be 0 in v1; readers reject any non-zero value
   8    16    salt
  24     4    time_cost    uint32 LE
  28     4    mem_cost     uint32 LE in KB
  32     4    parallelism  uint32 LE
  36    24    nonce
  60     4    ct_len       uint32 LE
  64    ct_len  ct         XChaCha20-Poly1305-IETF, AAD = bytes 0..63 inclusive (exactly 64 bytes)
```

Plaintext = `priv[32]`. K = Argon2id(passphrase, salt; T=time_cost, M=mem_cost, P=parallelism).

**AAD scope is exactly 64 bytes (the fixed header).** Nonce is included in AAD. This is intentional — wider AAD coverage is strictly more conservative. Test vectors are format-specific.

**v1 has no TLV trailer.** All `flags` bits MUST be zero in v1; readers reject any non-zero `flags` value. The TLV-trailer slot is reserved-not-implemented — the bit semantics will be assigned in a future format version when there's a concrete need.

If/when TLV is added: a TLV trailer is NOT integrity-protected by AEAD. Any data placed in the trailer can be tampered with without breaking decryption. A trailer MUST NOT carry security-critical data. Future versions may move the trailer inside the ciphertext if integrity is needed.

**Why:**
- Family-magic (`"KCAP"` + project_id) → the parser dispatches on the first 4 bytes.
- AAD covers full header → defends against tampering of an existing capsule. Does NOT alone defend against a malicious packer using low params — see D-15.
- Params-in-header → tunable per-capsule without a magic bump.
- Reserved flags → forward-compat for future non-security-critical extensions without assigning v1 semantics prematurely.

**Alternatives considered:**
- **Keep KCAP2 forever** — leaves gaps (no AAD, hardcoded params); rejected because three formats is too many.
- **Use a compact 8-byte packed `argon2_params` field** — saves 4 bytes per capsule; rejected for explicit-better-than-implicit (T/M/P named separately is more parseable in code review).

---

## D-15: KCAP3 receiver-side parameter floor and ceiling

**Decision:** KCAP3 readers enforce a policy range on Argon2id params from the header before calling `crypto_pwhash`:

- Floor: `time_cost ≥ 3 AND mem_cost ≥ 65536 (64 MiB) AND parallelism ≥ 1`.
- Ceiling: `time_cost ≤ 10 AND mem_cost ≤ 4194304 (4 GiB) AND parallelism ≤ 16`.

Any out-of-range param → reject with `EINVAL` and a clear error ("KDF params out of policy range") *before* the AEAD or KDF call.

**Why:**
- AAD-binding (D-13) defends against tampering an *existing* capsule's params — but a malicious packer can produce a *fresh* capsule with `time_cost=1, mem_cost=64` that AEAD-verifies fine. Without a receiver-side floor, the KDF runs at trivial cost and the protection is gone.
- Keeps the accepted parameter range close to the default while allowing future tuning.
- Ceiling prevents DoS via huge params (e.g., `mem_cost=2^32` would request 4 TiB).

**Alternatives considered:**
- **Hardcode params in receiver** — defeats D-13's params-in-header benefit. Rejected.
- **Use a stricter memory/parallelism floor** — adopting a higher floor such as M=128 MiB and P=4 would make the KCAP3 default (M=64 MiB, P=1) invalid. Rejected as inconsistent with our default.

---

## D-16: `/dev/shm` execution fallback — hardened

**Decision:** When `memfd_create` is unavailable, OR `fexecve` on a memfd returns `errno == ETXTBSY`, `elfdec-run` falls back to writing the plaintext binary to `/dev/shm/elfdec-<pid>` and exec'ing it from there. Any other `fexecve` errno is fatal and does NOT trigger the fallback. On the fallback path, the file is unlinked before exec so the plaintext is not reachable through the filesystem while the workload runs.

**Landed code state:**
- Fallback triggers **only** on `errno == ETXTBSY` after `fexecve`. Other errnos (`ENOEXEC`, `EACCES`, …) surface as fatal errors with no `/dev/shm` write. (AC-03-05(a))
- Fallback exec sequence: open RO fd → close writer → `unlink(tmp_path)` → `execveat(rofd, "", argv, envp, AT_EMPTY_PATH)`. The workload runs from an inode no longer reachable through any filesystem path. (AC-03-05(b/c))
- On exec **failure** through the fallback path: wipe the inode with random bytes via `/proc/self/fd/N`, close the fd, exit non-zero. (AC-03-04(b modern))
- Both fallback entry points (memfd unavailable + post-fexecve ETXTBSY) share the same hardened exec sequence.

**Kernel-version dependency (honest scope):**
The hardened fallback uses `execveat(2)` (Linux ≥ 3.19, syscall 322). On kernels that lack `SYS_execveat`, `execveat_compat()` returns `ENOSYS` and the fallback exits non-zero — there is no second-tier fallback. Practical impact:
- Kernels < 3.17: lack `memfd_create` *and* `execveat`. Encrypted execution unavailable. Fail-closed.
- Kernels 3.17–3.18: `memfd_create` works but `execveat` does not. The ETXTBSY fallback path is unreachable; primary memfd path must work.
- Kernels ≥ 3.19: full path available. This is the supported floor for ephrun.

**Existing mitigations in code (preserved):**
- `O_EXCL` on open prevents symlink races during the brief tmpfs creation window.
- File mode 0700 during the same window.

**Tests:** `test.sh` AC-03-04 / AC-03-05 / AC-03-07 cases — driven by an LD_PRELOAD shim (`ephrun/test_fexecve_shim.c`) that forces a chosen errno from `fexecve`, making the fallback path deterministic in CI.

**Why retain the fallback:**
- Some kernels return `ETXTBSY` on fexecve from a writable memfd; without fallback, those targets can't run encrypted ELFs at all.
- Removing the fallback would break some deployments (kernel-version-dependent).

**Why disclose:**
- The threat model could otherwise be read as "plaintext binary never lands on disk." This is false during the fallback window.
- Honest disclosure lets operators evaluate whether the fallback risk is acceptable for their deployment.

**Alternatives considered:**
- **Remove fallback entirely** — breaks ETXTBSY-affected kernels.
- **Disable fallback by default, opt-in via env var** — explicit but adds a footgun.
- **Use ramfs instead of tmpfs** — ramfs doesn't swap to disk; still root-readable. Marginal improvement.

---

## D-17: `elfdec-run` MUST scrub ephrun env vars before exec'ing the workload

**Decision:** Before `fexecve` / `execve`, `elfdec-run` MUST scrub the following environment variables from the child environment:

- `ELFDEC_CODE`
- `ELFDEC_KEYID`
- `ELFDEC_LABEL`
- `ELFDEC_KEYPATH`
- `ELFDEC_ALLOW_TRACE` (D-18 dev escape hatch — must not propagate)

The scrub uses `unsetenv` (or constructs a clean `envp` array) before exec. The variables are not visible to the executed workload or any process it spawns.

**Why:**
- `elfdec-run` would otherwise call `fexecve(fd, child_argv, environ)` and the full parent environ would be inherited. The decryption passphrase (`ELFDEC_CODE`) would leak to the workload, which:
  - May log it (rare, but possible).
  - Will expose it in `/proc/<workload-pid>/environ` for any process that can read it (root, same-uid).
  - Will pass it to any child process the workload spawns.
- The workload has no business reading these variables. They are inputs to `elfdec-run`, not to the workload.

**Alternatives considered:**
- **Document as an operator concern, expect the operator to scrub.** Rejected: easy to forget, default behavior should be safe.
- **Pass the passphrase via stdin pipe instead of env var.** Larger change; doesn't compose with `binfmt_misc` integration.

**Test impact:** AC under AC-03 verifies that the workload's `/proc/self/environ` does NOT contain `ELFDEC_*` after exec.

---

## D-18: `elfdec-run` refuses to start under a ptrace tracer (defense-in-depth)

**Decision:** Before any sensitive work (capsule unwrap, ELF decrypt, memfd write), `elfdec-run` reads `/proc/self/status` and aborts if `TracerPid != 0`. Bypass: `ELFDEC_ALLOW_TRACE=1` (dev escape hatch). The bypass var is itself in the D-17 scrub list so it cannot leak into the workload.

**Why:**
- Casual `gdb -p <pid>` and same-uid `strace -p` attaches can dump the decrypted priv key, the passphrase-derived AEAD key, or the plaintext binary out of `elfdec-run`'s address space. The check denies that path.
- Reading `/proc/self/status` has zero side effects; signal-delivery semantics are untouched.

**Why NOT `PTRACE_TRACEME`:**
- `PTRACE_TRACEME` changes signal-delivery semantics (the kernel synthesises stops on every signal), and that state is inherited across `fexecve`. The result is broken `SIGINT` / `SIGTERM` handling in the workload — a correctness regression for a defense-in-depth check.
- Reading `TracerPid` is a one-shot inspection of an existing kernel-maintained value. No state change.

**Limits — explicitly NOT a security claim:**
- A root process on the host can clear `TracerPid` (e.g. by detaching mid-run) or replace `/proc/self/status` via mount tricks.
- A kernel rootkit can lie about `TracerPid`.
- TOCTOU: a tracer can attach *after* the check passes. The check defends startup, not the running process.
- Use case: raise the bar against opportunistic interactive debugging, not defeat a determined root attacker.

**Tests:** `test.sh` runs four cases — baseline (no tracer), under `strace -f` (must abort), `ELFDEC_ALLOW_TRACE=1 strace -f` (bypass works), and env-scrub verification (workload's `/proc/self/environ` does not contain `ELFDEC_ALLOW_TRACE`).

---

## D-19: Loader-tampering env scrub + mlock on plaintext heap (defense-in-depth)

**Decision:** `elfdec-run` does two additional defense-in-depth things on top of D-17 (ELFDEC_* scrub):

1. **Loader-tampering env scrub.** A second deny-list (`LOADER_SCRUB_ENV[]`) is stripped from BOTH `elfdec-run`'s own `environ` (via `unsetenv` early in `main`, before `sodium_init`) AND from the workload's envp (via `build_clean_envp`). The list follows common loader-tampering deny-list patterns: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, `LD_PROFILE`, `GCONV_PATH`, `HOSTALIASES`, `LOCPATH`, `NLSPATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `BASH_ENV`, `ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `_JAVA_OPTIONS`, `JAVA_TOOL_OPTIONS`, `CDPATH`, `GLOBIGNORE`.

2. **mlock + munlock on plaintext + ciphertext heap buffers.** Pins the decrypted ELF plaintext and the sealed-box ciphertext out of swap for the brief window between decrypt and write-to-memfd. Also moves `prctl(PR_SET_DUMPABLE, 0)` and `prctl(PR_SET_NO_NEW_PRIVS, 1)` to the very top of `main` so they cover the unwrap window, not just the post-decrypt window.

**Why:**
- LD_PRELOAD scrub: by the time `main()` runs, glibc has already honored `LD_PRELOAD`, so the unset on our own env does NOT protect this process from a preload that was set when we were exec'd (STATIC=1 is the answer for that). What it DOES protect: anything we fork+exec, getenv lookups, and the workload — which is dynamically linked and would otherwise inherit the var. Stripping is bar-raising defense-in-depth, not a security guarantee.
- mlock: prevents the plaintext ELF + sealed-box ciphertext from being paged to swap during the brief decrypt-write window. `sodium_munlock` is paired (it implies memzero, so the explicit memzero just before is redundant but harmless). Failures (RLIMIT_MEMLOCK on hardened distros) are non-fatal — defense-in-depth, not a hard requirement.
- Early `PR_SET_DUMPABLE`: previously ran AFTER decryption, so a SIGSEGV during unwrap would produce a core dump containing key material. Moving it before `sodium_init` closes that window.

**Limits — explicitly NOT security claims:**
- Root with `/proc/<pid>/mem` access can read every buffer mlock'd or not.
- Root can re-set `LD_PRELOAD` in the workload's address space post-fork.
- The defense raises the cost of casual same-uid attacks and accidents (swap leakage on suspend, core dumps in distro crashdump dirs); it does not stop a hostile host kernel.

**Tests:** AC-03-07 covers `LD_PRELOAD`-style env-leak prevention via the env_dump workload + `LD_PRELOAD`-driven `test_fexecve_shim.so`.

**Alternatives considered:**
- **Allow-list instead of deny-list** for envp — too aggressive, breaks workloads expecting to see PATH/HOME/USER/etc.
- **Skip mlock entirely, rely on PR_SET_DUMPABLE** — PR_SET_DUMPABLE prevents core dumps but not swap, and on a busy host the plaintext could touch swap during a multi-MB decrypt+write.
- **MADV_DONTDUMP** on the heap regions — redundant with PR_SET_DUMPABLE=0 unless `/proc/sys/fs/suid_dumpable=2` raises us back to dumpable (rare). Skipped.

---

## D-20: Kernel-version-tolerant `MFD_EXEC` handling in `memfd_create_compat`

**Decision:** `elfdec-run.c` does NOT supply a local `#define MFD_EXEC` fallback. The `MFD_EXEC` bit is OR-ed into the `memfd_create` flags only when the system headers actually define it (`#ifdef MFD_EXEC` guards the call site). `memfd_create_compat` retries without `MFD_EXEC` on `EINVAL`, so a userspace built on a 6.3+ box (where headers define the flag) still runs on a pre-6.3 kernel that doesn't recognise the bit.

**Why:**
- The kernel value of `MFD_EXEC` is **`0x0010`**; it was added in Linux 6.3 (May 2023). Pre-6.3 kernels reject any unknown bit in `memfd_create`'s flags argument with `EINVAL`.
- Ubuntu 22.04's `linux/memfd.h` does not define `MFD_EXEC` at all, so a previous local fallback `#define MFD_EXEC 0x0008` was always active on that distro. **`0x0008` is the wrong value** (it is `F_SEAL_WRITE` — almost certainly a copy-paste from the seal block above). The kernel rejected the call with `EINVAL`, every `elfdec-run` invocation on Ubuntu 22.04 silently fell through to the `/dev/shm` fallback path, and the `LD_PRELOAD` shim that drives AC-03-05's negative case was bypassed entirely (no `fexecve` call ever happened).
- A correct local fallback `#define MFD_EXEC 0x0010` would *also* be wrong: passing the bit on a pre-6.3 kernel still triggers `EINVAL`. The kernel-version tolerance has to live at the syscall, not in a header `#define`.

**Alternatives considered:**
- **Local `#define MFD_EXEC 0x0010`** — fixes the value but still breaks on pre-6.3 kernels. Rejected.
- **Always pass the bit, accept `EINVAL` and fall through to `/dev/shm`** — defeats the point of `memfd` on every pre-6.3 host. Rejected.
- **Probe `MFD_EXEC` support at startup, cache the result** — adds startup latency and complexity for a one-bit decision. Rejected: the EINVAL retry inside `memfd_create_compat` is cheaper and equally correct.

**Tests:** AC-03-05(a/b/c) were silently passing on kernel 6.8 only because `MFD_EXEC` was defined by 6.x kernel headers, so the local `#define` never fired. Running `test.sh` on Ubuntu 22.04 / kernel 5.15 surfaced the bug immediately: `strace` showed `memfd_create(..., MFD_CLOEXEC|MFD_ALLOW_SEALING|0x8) = -1 EINVAL`, the `/dev/shm` fallback fired, and the AC-03-05(a) negative-case shim never got invoked. After this fix, AC-03-05(a) passes on both 6.8 and 5.15.
