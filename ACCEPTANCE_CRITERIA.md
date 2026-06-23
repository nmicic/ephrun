# ephrun — Acceptance Criteria

All criteria are testable pass/fail. No "works correctly" without specifics.

References: `SPEC.md` (current system), `DECISIONS.md` (D-N decisions).

---

## AC-01  KCAP3 — Layer-4 capsule format

Per `DECISIONS.md` D-13. KCAP3 writer + dual-read alongside existing KCAP1/KCAP2.

### AC-01-A  Wire format

  AC-01-A-01  `kcap_pack` writes a capsule whose first 4 bytes are ASCII `KCAP`
              (0x4B 0x43 0x41 0x50).
  AC-01-A-02  Byte 4 (version) of a fresh capsule == 0x01. Any value other than
              0x01 (i.e. 0x00 through 0xFF except 0x01) MUST cause readers to
              reject with a clear error (no Argon2id derivation, no AEAD open
              attempted). Allowlist semantics — only the explicitly-supported
              version is accepted.
  AC-01-A-03  Byte 5 (project_id) of an ephrun capsule == 0x01. Readers MUST
              reject project_id 0x00 and 0xFF as reserved sentinels.
  AC-01-A-04  Bytes 6-7 (flags) — **all bits MUST be zero in v1.** TLV trailer
              is reserved-not-implemented (see D-13). Any non-zero `flags` value
              MUST cause readers to reject with "unknown flags: 0x<hex>". This
              keeps the bit-assignment slot open for a future format version
              without exposing a live rejection path for an unimplemented feature.
  AC-01-A-05  Total fixed header is exactly 64 bytes. Layout matches D-13 byte-for-byte.
  AC-01-A-06  `salt[16]` produced by `randombytes_buf` — two consecutive `kcap_pack`
              runs with identical input produce different `salt` values
              (probability of collision negligible).
  AC-01-A-07  `nonce[24]` produced by `randombytes_buf` — same uniqueness property.
  AC-01-A-08  `ct_len` (bytes 60-63, little-endian uint32) == 32 + 16 = 48 for raw-priv
              plaintext (`priv[32]` + Poly1305 tag).
  AC-01-A-09  `time_cost` (bytes 24-27) == 3 by default. `mem_cost` (bytes 28-31)
              == 65536 (i.e. 64 MiB in KB). `parallelism` (bytes 32-35) == 1.
  AC-01-A-10  Total capsule size for default params + raw-priv + no TLV: 64 + 48 = 112 bytes.
              `wc -c capsule.bin` returns 112.

### AC-01-B  KDF and AEAD

  AC-01-B-01  Capsule key derivation: `K = Argon2id(passphrase, salt; T=time_cost,
              M=mem_cost, P=parallelism)`, output 32 bytes. Verifiable by
              independent reimplementation against test vectors (see AC-01-D).
  AC-01-B-02  AEAD: `XChaCha20-Poly1305-IETF.Seal(K, nonce, plaintext=priv[32],
              AAD=bytes[0..63] inclusive — exactly 64 bytes)`. The AAD covers
              the full fixed header including nonce and ct_len. Any
              implementation that uses a different AAD length or offset
              produces capsules that fail to verify on a reference reader.
  AC-01-B-03  AAD tamper attack (in-policy mutation): take a valid KCAP3 capsule
              packed with `time_cost=3`, change `time_cost` to `4` in the header
              (still inside D-15 policy range), attempt unlock with the correct
              passphrase → AEAD verification MUST fail with a MAC error.
              Rationale: must use an in-policy mutation, otherwise the receiver
              rejects on policy (D-15) before AEAD runs and the AC tests the
              wrong layer.
  AC-01-B-04  AAD tamper — flip one bit in the magic, version, project_id,
              salt, nonce, or ct_len fields → AEAD verification MUST fail.
              Verifies AAD coverage of the full 64-byte header.
  AC-01-B-05  Wrong passphrase: AEAD verification fails, no plaintext leaks,
              no segfault.
  AC-01-B-06  KDF timing sanity: end-to-end unwrap takes ≥ 50 ms on a 2020-era
              x86_64 CPU (matches existing `kcap_kdf_test` floor). Detects
              accidental short-circuit.
  AC-01-B-07  Receiver param-floor enforcement (D-15): a freshly-packed KCAP3
              capsule with `time_cost=1` (or `mem_cost < 65536`, or
              `parallelism < 1`) MUST be rejected by the reader BEFORE
              Argon2id is invoked. Error message names the offending param.
              This defends against a malicious packer (where AAD-binding
              alone does not, since the packer controls the AAD).
  AC-01-B-08  Receiver param-ceiling enforcement (D-15): a capsule with
              `mem_cost > 4194304 (4 GiB)` or `time_cost > 10` or
              `parallelism > 16` MUST be rejected before Argon2id is invoked.
              Defends against DoS via huge params.

### AC-01-C  Round-trip and round-trip resilience

  AC-01-C-01  Round-trip: `kcap_pack --in priv.bin --out cap.bin --code "x"`,
              then `kcap_unpack --in cap.bin --code "x"` (or equivalent in
              `elfdec-run`) → recovers `priv.bin` byte-for-byte.
  AC-01-C-02  Empty passphrase rejected at pack time with error "code required".
  AC-01-C-03  Passphrases up to at least 4096 bytes accepted at pack time and
              correctly unwrap.
  AC-01-C-04  Truncated capsule (last byte missing) rejected with size mismatch
              error before any KDF work is performed.
  AC-01-C-05  Oversized capsule (extra trailing bytes when no TLV flag set)
              rejected with size mismatch error before any KDF work.

### AC-01-D  Cross-platform reference vectors

  AC-01-D-01  A test fixture `testdata/kcap3.bin` is committed, generated with a
              fixed passphrase (`"kcap3-fixture-code"`) and fixed
              `priv.bin = bytes(0..31)`. The KDF salt and nonce in the fixture
              are pinned (not random) so the file is reproducible.
  AC-01-D-02  Linux build of `kcap_kdf_test` decrypts `testdata/kcap3.bin` with
              the fixture code → output equals `bytes(0..31)`.
  AC-01-D-03  macOS build of `kcap_kdf_test` decrypts `testdata/kcap3.bin` →
              identical output. Confirms cross-platform binary compatibility.

### AC-01-E  Backward compatibility

  AC-01-E-01  Existing `testdata/kcap1.bin` (committed pre-KCAP3) still decrypts
              successfully via `elfdec-run` with the original `kcap1-fixture-code`.
  AC-01-E-02  A KCAP2 capsule produced by the pre-KCAP3 `kcap_pack` build still
              decrypts successfully via the post-KCAP3 `elfdec-run`.
              (Add `testdata/kcap2.bin` fixture if not already present.)
  AC-01-E-03  `kcap_pack` (post-change) writes ONLY KCAP3. It MUST NOT produce
              KCAP1 or KCAP2 magic. Verify: `head -c 4 capsule.bin` == `KCAP`,
              `head -c 5 capsule.bin | tail -c 1` == `\x01`, NOT `KCAP1\0` or `KCAP2\0`.
  AC-01-E-04  `git grep -n 'KCAP1\\\\0\\|KCAP2\\\\0' ephrun/` returns matches
              ONLY in (a) elfdec-run.c read path, (b) libexec_key.h read path,
              (c) kcap.h legacy KDF block, (d) kcap_kdf_test.c. NO matches in
              kcap_pack.c.

### AC-01-F  Build and test integration

  AC-01-F-01  `make` from repo root completes with no warnings on Linux x86_64
              under `-O2 -Wall -Wextra -Wpedantic -fstack-protector-strong
              -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now`.
  AC-01-F-02  `make` completes with no warnings on macOS arm64 under matching
              flags (minus Linux-only `-Wl,-z,...`).
  AC-01-F-03  `make -C ephrun check` runs `kcap_kdf_test` and all assertions
              pass on both platforms.
  AC-01-F-04  `bash test.sh` (Linux) reports 100% passed, including new
              KCAP3-specific cases.
  AC-01-F-05  `make clean && make` produces no extra files; working tree clean
              after build (no compiled artifacts tracked).

### AC-01-G  Code hygiene

  AC-01-G-01  No new TODOs or FIXMEs introduced.
  AC-01-G-02  No new `#pragma` other than existing struct-pack patterns.
  AC-01-G-03  All sensitive buffers (passphrase-derived K, plaintext priv) wiped
              with `sodium_memzero` before scope exit / `free`.
  AC-01-G-04  No dynamic allocation > capsule size + 4096 bytes during unwrap
              (bound checked by code review).
  AC-01-G-05  `kcap_pack`'s output file mode is 0600 if newly created (current
              `kcap_pack` does not set this — opportunity to fix).

---

## AC-03  Threat-model invariants (cross-cutting)

  AC-03-01  No passphrase, raw priv key, or session key bytes appear in `strings`
            output of any deployed file (capsules, .elfenc).
  AC-03-02  No passphrase, raw priv key, or session key appear in process stderr,
            stdout, or any log file. Verify via grep on captured output.
  AC-03-03  After `elfdec-run` exec succeeds via the memfd path, no plaintext
            binary exists on any persistent filesystem. Verify:
            `find / -path /proc -prune -o -path /sys -prune -o -path /dev/shm -prune
             -o -type f -newer <test_start_marker> -print | xargs -I{} sh -c
             'head -c4 {} 2>/dev/null | grep -q "^\\x7fELF" && echo {}'`
            returns no path matching the test binary's plaintext signature.
  AC-03-04  `/dev/shm` fallback exec-failure hygiene (LANDED,
            driven by `ephrun/test_fexecve_shim.c` LD_PRELOAD shim that
            forces `fexecve` errno):
            (a) during exec attempt, the temp file briefly exists on tmpfs
                with mode 0700.
            (b) on exec FAILURE: the inode is wiped with random bytes via
                `/proc/self/fd/N` and the fd closed; `ls /dev/shm/elfdec-*`
                returns no matches after the failed run.
            (c) on exec SUCCESS via the fallback path: `unlink(tmp_path)`
                runs before `execveat`, so the workload runs from an inode
                with zero filesystem references; `ls /dev/shm/elfdec-*`
                returns no matches while the workload is alive.

  AC-03-05  `/dev/shm` fallback gating + execveat path (LANDED):
            (a) Fallback only triggers when `errno == ETXTBSY` after the
                initial `fexecve`. Any other errno surfaces immediately as
                a fatal error without writing plaintext to /dev/shm.
                Verified by `test_fexecve_shim.c` forcing ENOEXEC/EACCES.
            (b) After unlink-before-exec, the file is no longer reachable
                on the filesystem — `execveat(rofd, "", argv, envp,
                AT_EMPTY_PATH)` runs the workload from the unlinked inode.
            (c) Test harness for (b): after successful workload start,
                `ls /dev/shm/elfdec-*` returns no matches.
            **Kernel floor:** path requires Linux ≥ 3.19 (execveat). On older
            kernels, `execveat_compat` returns ENOSYS and the fallback
            exits non-zero. Documented in D-16.

  AC-03-06  Process memory hygiene: `gcore` of `elfdec-run` immediately after
            successful exec → core dump does NOT contain plaintext priv or
            passphrase-derived K (sodium_memzero verified).
            Note: best-effort; `PR_SET_DUMPABLE=0` should prevent gcore from
            succeeding at all post-prctl. AC verifies the prctl runs.

  AC-03-07  Env-var scrubbing before exec (D-17): the executed workload's
            `/proc/self/environ` MUST NOT contain `ELFDEC_CODE`, `ELFDEC_KEYID`,
            `ELFDEC_LABEL`, `ELFDEC_KEYPATH`, or
            `ELFDEC_ALLOW_TRACE` (the D-18 dev escape hatch must not leak).
            Verify with a tiny test workload that prints its own env. Tested
            for both the memfd path and the /dev/shm fallback path.

  AC-03-08  Loader-scrub before exec (D-19): when `elfdec-run`'s parent sets
            `LD_PRELOAD`, `NODE_OPTIONS`, `BASH_ENV` (or any other entry in
            `LOADER_SCRUB_ENV[]`), the workload's `/proc/self/environ` MUST
            NOT contain those variables. Test uses a real `.so` for the
            `LD_PRELOAD` value (e.g. `/lib/x86_64-linux-gnu/libnss_files.so.2`)
            so the path glibc would actually honor is exercised, not a bogus
            string. Defense-in-depth: closes one vector for hostile-parent
            interposition into the workload; root with /proc access still wins.

  AC-03-09  Argon2id under cgroup memory pressure: when run inside a cgroup
            with `memory.max = 96MiB` (just above the 64 MiB Argon2id allocation),
            `elfdec-run` either (a) succeeds with a clean exit, or (b) fails
            with a clear `ENOMEM`-flavored error message — NOT a SIGKILL or
            segfault. Validates the OOM error path.

---

## AC-04  Documentation invariants

  AC-04-01  `SPEC.md` reflects the KCAP3 wire format.
  AC-04-02  `DECISIONS.md` D-13 status flag reflects the shipped KCAP3 writer.
  AC-04-03  `README.md` quick-start section uses `KCAP3` magic in any examples
            that show capsule magic bytes.

---

## Non-goals

This project deliberately does NOT do the following:

- KCAP2/KCAP1 deprecation (kept as read-only indefinitely).
- Cross-arch beyond x86_64 / arm64 Linux.
- Windows / *BSD support.
