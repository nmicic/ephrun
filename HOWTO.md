<!-- Copyright (c) 2025 Nenad Micic <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# HOWTO — ephrun

Operational guide. Top to bottom this is the path from `git clone` to a
running encrypted ELF on a Linux target. For why the system is shaped
the way it is, see `README.md` and `DECISIONS.md`. For the threat model
(what this defends against, what it does not), see `SECURITY.md`. For
the wire formats, see `SPEC.md`. This file does not duplicate any of
that.

## 1. What this is, in 3 lines

Encrypted ELF distribution to Linux hosts where you do not trust root —
rented VMs, cloud containers, generic IaaS. Defends the binary at rest
against disk reads, image extraction, and offline brute force; does
**not** defend the running process against `/proc/<pid>/mem` or live
memory forensics by hostile root. Threat model details and the full
list of out-of-scope adversaries are in `SECURITY.md`.

## 2. Prerequisites

**Distro packages (Ubuntu / Debian).**

```sh
sudo apt-get install -y build-essential libsodium-dev libkeyutils-dev
```

`libssl-dev` is needed only for `keyring_crypto_test`; skip it for
production deploys. macOS can build the cross-platform tools (`genkey`,
`elfenc_pack`, `kcap_pack`, `kcap_unpack`, `keypush_send`) with
`brew install libsodium`; `elfdec-run` and `keypushd` are Linux-only.

**Kernel floor.**

- Linux >= 3.19 is the supported floor for `elfdec-run`. The
  `/dev/shm` ETXTBSY fallback uses `execveat(2)` (3.19+) — pre-3.19
  kernels fail closed instead of running encrypted ELFs (D-16).
- `MFD_EXEC` is best-effort. Userspace built on a 6.3+ box still runs
  on a 5.15-era kernel: `memfd_create_compat` retries without the bit
  on `EINVAL` (D-20).
- Validated on v5.15, v6.1, v6.5, v6.8 — see §7 for the matrix.

**Optional.**

- `systemd-run --user --scope` — only needed for AC-03-09 (cgroup OOM
  validation in `test.sh:609-666`). Not needed at runtime.
- `strace` — only needed to exercise the D-18 ptrace defense tests.

## 3. Quick start (golden path)

Mode 4 (file-based key) is the simplest deployment posture and the
right starting point. This is the case validated by `test.sh:150-175`.

```sh
git clone https://github.com/nmicic/ephrun && cd ephrun
make                                             # builds ephrun/ + keypush/
cd ephrun

./genkey                                         # → pub.bin, priv.bin (32 B each)
gcc -O2 hello.c -o hello                         # any ELF works; hello is the test fixture
./elfenc_pack pub.bin hello hello.elfenc         # → ELFENC1 sealed-box

mkdir -p /tmp/elfenc_keys && cp priv.bin /tmp/elfenc_keys/
chmod 600 /tmp/elfenc_keys/priv.bin

ELFDEC_KEYPATH=/tmp/elfenc_keys ./elfdec-run ./hello.elfenc
# → hello from encrypted ELF!
```

`pub.bin` is **not** required at runtime — `elfdec-run` derives it from
`priv.bin` via `crypto_scalarmult_base`. Only the priv key reaches the
target.

For a static binary that runs on hosts without matching glibc / libsodium:

```sh
make -C ephrun clean && make -C ephrun STATIC=1
```

This is not optional in practice. A dynamic `elfdec-run` built on a
modern Ubuntu / Debian will fail on an older target with
`/lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.38' not found`
(or similar) — the build host's glibc baseline gets baked into the
binary at link time. Ship the static build for cross-distro deploys.
The static binary is ~1.2 MB (vs ~32 KB dynamic) but has no runtime
dependencies beyond a 3.19+ kernel.

## 4. The four key-sourcing modes

`elfdec-run` tries the modes in this priority order; the first success
wins (D-4, `elfdec-run.c:498-574`):

| # | Trigger env var          | Source                                                      |
|---|--------------------------|-------------------------------------------------------------|
| 1 | `ELFDEC_CODE`            | KCAP3 / KCAP2 / KCAP1 capsule (keyring or `$ELFDEC_KEYPATH`) |
| 2 | `ELFDEC_KEYID`           | Raw priv by numeric keyring ID                              |
| 3 | `ELFDEC_LABEL`           | Raw priv by keyring search `elfdec:<label>`                 |
| 4 | `ELFDEC_KEYPATH` / `~/.elfenc/` | `priv.bin` on disk                                   |

If `ELFDEC_LABEL` is unset, the canonical realpath of the `.elfenc`
file is used as the label for tier 3.

### Mode 1 — Capsule (`ELFDEC_CODE`)

Use when you want the priv key never to land on the target as raw
bytes. The capsule is XChaCha20-Poly1305 / Argon2id-wrapped (D-1, D-13)
and is safe to ship next to the `.elfenc` file. Default Argon2id cost
is T=3, M=64 MiB, P=1; receiver enforces D-15 floor and ceiling before
calling the KDF. Validated by `test.sh:209-239` (binary capsule on
disk) and `test.sh:311-328` (capsule in keyring).

Build-side:

```sh
./kcap_pack --label prod/myapp --code "correct horse battery staple lattice 7" \
            --in priv.bin --out capsule.bin
# → 112-byte KCAP3 file (64-byte header + 48-byte ciphertext)
```

Deploy `myapp.elfenc` and `capsule.bin` to the target. `priv.bin` stays
on the builder. Then on the target:

```sh
# Option A — capsule on disk
mkdir -p /opt/myapp/keys && cp capsule.bin /opt/myapp/keys/
ELFDEC_CODE="correct horse battery staple lattice 7" \
ELFDEC_KEYPATH=/opt/myapp/keys \
    ./elfdec-run ./myapp.elfenc

# Option B — capsule in the kernel keyring (no disk file)
keyctl padd user "elfdec_caps:prod/myapp" @s < capsule.bin
ELFDEC_CODE="correct horse battery staple lattice 7" \
ELFDEC_LABEL="prod/myapp" \
    ./elfdec-run ./myapp.elfenc
```

Capsule lookup order (`elfdec-run.c:500-509`):

1. Keyring: `elfdec_caps:<ELFDEC_LABEL>` searched in `@s` then `@u`.
2. File: `$ELFDEC_KEYPATH/capsule.bin`, then legacy
   `$ELFDEC_KEYPATH/capsule.json` (deprecated, read-only).

Passphrase entropy is the operator's responsibility — Argon2id raises
the per-guess cost to ~100 ms on a modern CPU; it does not save weak
passphrases. See `SECURITY.md` §4 item 3.

### Mode 2 — Keyring by numeric ID (`ELFDEC_KEYID`)

Use when a separate process injected the key and handed you back the
numeric ID (e.g. `keypushd` ACK, `elfdec-ssh-pushkey.sh`, or a parent
script). Validated by `test.sh:177-194`.

```sh
# Inject (32-byte raw priv into session keyring, name "elfdec:prod/myapp")
KEYID=$(keyctl padd user "elfdec:prod/myapp" @s < priv.bin)
keyctl setperm "$KEYID" 0x3f030000     # owner: view+read; possessor: all
keyctl timeout "$KEYID" 300            # auto-expire 5 minutes

# Run
ELFDEC_KEYID="$KEYID" ./elfdec-run ./myapp.elfenc
```

### Mode 3 — Keyring by label (`ELFDEC_LABEL`)

Use when the key is in the keyring with a known label and the consumer
shouldn't have to track the numeric ID. `elfdec-run` searches for a
key named `elfdec:<ELFDEC_LABEL>` in `@s` then `@u`. Validated by
`test.sh:196-204`.

```sh
keyctl padd user "elfdec:prod/myapp" @s < priv.bin
ELFDEC_LABEL="prod/myapp" ./elfdec-run ./myapp.elfenc

# If ELFDEC_LABEL is unset, realpath(.elfenc) is used as the label.
./elfdec-run ./myapp.elfenc
# → searches keyring for "elfdec:/abs/path/to/myapp.elfenc"
```

For local injection helpers see `ephrun/add_keyring4.sh` (root + user
detection, perm fallback) and `ephrun/add_keyring8.sh` (concise
production version). For SSH push see `ephrun/elfdec-ssh-pushkey.sh`.

### Mode 4 — File-based (`ELFDEC_KEYPATH` or `~/.elfenc/`)

Simplest. Only `priv.bin` is needed on the target — `pub.bin` is
derived at runtime. Use for single-host dev or for hosts where you do
not want capsule overhead. Validated by `test.sh:150-175`.

```sh
# Custom dir
sudo mkdir -p /etc/elfenc
sudo cp priv.bin /etc/elfenc/ && sudo chmod 600 /etc/elfenc/priv.bin
ELFDEC_KEYPATH=/etc/elfenc ./elfdec-run ./myapp.elfenc

# Default dir — no env vars
mkdir -p ~/.elfenc && cp priv.bin ~/.elfenc/ && chmod 600 ~/.elfenc/priv.bin
./elfdec-run ./myapp.elfenc
```

Filesystem permissions are the only barrier here. On a host where root
is hostile, Mode 1 (capsule) is materially better.

## 5. Capsule operations

### `kcap_pack` — produce a KCAP3 capsule

Source: `ephrun/kcap_pack.c:50-75`.

| Flag        | Required | Description                                                       |
|-------------|----------|-------------------------------------------------------------------|
| `--label`   | yes      | Label string. Recorded for CLI sanity; KCAP3 has no label field.  |
| `--code`    | yes      | Passphrase. Empty string is rejected ("code required").           |
| `--in`      | no       | Path to 32-byte raw priv. Stdin if omitted.                       |
| `--out`     | no       | Output path. Stdout if omitted. Output mode is 0600 when created. |
| `--ttl N`   | no       | **Deprecated.** Accepted for CLI compat, prints warning, ignored. |
| `--json`    | no       | **Deprecated.** Exits 2 with "JSON output deprecated in KCAP3".   |

`kcap_pack` writes only KCAP3 (AC-01-E-03). KCAP1 / KCAP2 are
read-only legacy formats kept readable by `elfdec-run` and
`libexec_key.h` for migration; rotate by re-packing the original
`priv.bin` with `kcap_pack` and deploying the new capsule. The format
is dispatched by family magic so old capsules keep working until you
replace them.

### `kcap_unpack` — cross-platform CLI unwrap (KCAP3 only)

Source: `ephrun/kcap_unpack.c:53-75`. Builds on Linux and macOS; no
keyring dependency.

```sh
kcap_unpack --in capsule.bin --code "passphrase" > priv.bin
KCAP_CODE="passphrase" kcap_unpack --in capsule.bin > priv.bin
```

This tool is for fixture verification, CI checks, and tooling pipes —
not for production deployment. `elfdec-run` consumes capsules
in-process; piping the priv key through a CLI defeats the point of the
capsule layer.

## 6. Remote key push

Two options exist today. Pick based on whether you have SSH to the
target.

### SSH push — `elfdec-ssh-pushkey.sh`

Streams the raw priv over SSH stdin into the remote kernel keyring.
The key never touches the remote disk.

```sh
./elfdec-ssh-pushkey.sh -H user@remote -l prod/myapp -k priv.bin -t 300
# Returns the keyring ID; on the remote:
#   ELFDEC_KEYID=<returned_id> /usr/local/bin/elfdec-run ./myapp.elfenc
```

### UDP push — `keypushd` + `keypush_send`

Use when SSH is unavailable. `keypushd` is **transitional** (D-7) — the
honest replacement going forward is to ship a KCAP3 capsule over any
standard channel (`scp`, HTTPS, tarball) since the capsule is safe at
rest. Don't add features here.

`keypushd` CLI flags (`keypush/keypushd.c:196-307`):

| Flag           | Default     | Description                                          |
|----------------|-------------|------------------------------------------------------|
| `--bind IP`    | required    | UDP bind address.                                    |
| `--port N`     | `0` (random)| UDP port; 0 = OS picks free.                         |
| `--label L`    | unset       | Default label if sender omits one.                   |
| `--ttl N`      | `300`       | Max key TTL in seconds (server-side cap).            |
| `--window N`   | `60`        | Bootstrap-token expiry in seconds.                   |
| `--detach`     | off         | Fork to background after printing bootstrap JSON.    |
| `--link-user`  | off         | Also link key into `@u` (persists across sessions).  |

`keypush_send` CLI flags (`keypush/keypush_send.c:50-67`):

| Flag                | Default  | Description                                          |
|---------------------|----------|------------------------------------------------------|
| `--ip IP`           | required | Target IP.                                           |
| `--port N`          | required | Target UDP port.                                     |
| `--srv-pk-b64 B64`  | required | `srv_pk` from bootstrap JSON.                        |
| `--token T`         | required | `token` from bootstrap JSON.                         |
| `--label L`         | required | Key label (e.g. `prod/myapp`).                       |
| `--ttl N`           | `300`    | Requested TTL (capped by server `--ttl`).            |
| `--wait-ack`        | off      | Wait up to 3s for ACK/NAK JSON reply.                |

Walkthrough:

```sh
# On the TARGET
./keypushd --bind 0.0.0.0 --port 9999 --label prod/myapp --ttl 300
# {"ip":"0.0.0.0","port":9999,"srv_pk":"xK7b+...","token":"K3J7QRST...","expires":...}

# Copy srv_pk + token to the control machine out of band, then on the CONTROL host
cat priv.bin | ./keypush_send \
    --ip <TARGET_IP> --port 9999 \
    --srv-pk-b64 "xK7b+..." --token "K3J7QRST..." \
    --label prod/myapp --ttl 300 --wait-ack
# {"ok":true,"keyid":827867509,"ttl":300}

# Back on the TARGET
ELFDEC_LABEL="prod/myapp" ./elfdec-run ./myapp.elfenc
```

`keypushd` has no rate limiting; the one-shot bootstrap window is the
only mitigation. Run it just long enough to push the key, then stop it.
Leaving it on a public-IP host is misuse (`SECURITY.md` §4 item 10).

`keypushd` exits after one successful payload. A `kill` of its PID
after the push will return non-zero because the process is already
gone — that is the intended one-shot lifecycle, not an error.

## 7. keyctl quick reference & Linux gotchas

The `elfdec-run` keyring path uses libkeyutils against the kernel
session keyring (`@s`) and user keyring (`@u`). A few non-obvious
things bite first-time users:

### Inspect the keyring

```sh
keyctl show @s              # tree view of session keyring
keyctl list @s              # one-line-per-key form
keyctl rdescribe <KEYID>    # type;UID;GID;perms;description
keyctl read <KEYID>         # NOT recommended — prints the key bytes hex
keyctl pkey_query <KEYID>   # capabilities (for asymmetric keys)
```

`keyctl show @s` typically shows `_ses → _uid.<UID>` — that nested
keyring entry is normal; it is the user keyring linked into the
session keyring by libpam's `pam_keyinit.so`.

### Tier shadowing (the "why does Mode 4 not fire?" gotcha)

`elfdec-run` walks the four key sources in priority order: capsule,
`ELFDEC_KEYID`, `ELFDEC_LABEL` (with `realpath(.elfenc)` as default
label), then `priv.bin` on disk. If you previously seeded
`elfdec:<realpath>` into `@s`, the disk path will never be tried even
when the env vars are unset, because tier 3 wins first.

```sh
keyctl clear @s             # nuke everything in the session keyring
keyctl unlink <KEYID> @s    # selective removal
keyctl revoke <KEYID>       # mark unusable without removing the link
```

Use `keyctl clear @s` between Mode-3 and Mode-4 tests. Symlinks matter
too: tier 3's default label uses `realpath()`, so the keyring entry
must be named `elfdec:<canonicalized-absolute-path>`, not the relative
or symlinked path you typed on the command line.

### Permission bits

`keyctl setperm 0x3f030000` (used in §4 Mode 2) decodes as:

| nibble | bits | meaning |
|--------|------|---------|
| `3f`   | possessor | view + read + write + search + link + setattr |
| `03`   | owner | view + read |
| `00`   | group | none |
| `00`   | other | none |

Possessor = "any process that has the key linked into a keyring it
holds". For most workloads on the same UID, leaving owner=`view+read`
is enough; processes do not need `write` to *use* a key, only to
modify it.

### TTL behaviour

`keyctl timeout <KEYID> <SECONDS>` arms a kernel-side expiry. After
the deadline:

- `keyctl read` returns `Key has expired` (errno `EKEYEXPIRED`).
- `keyctl_search` returns `No such file or directory`.
- The link itself stays until `keyctl gc` runs or you `unlink` it.

`elfdec-run` propagates `EKEYEXPIRED` up the same path as "key not
found" — the user-visible message is still `keyctl_search ... No such
file or directory`. If a previously working key suddenly stops, check
`keyctl rdescribe <KEYID>` for an `expired` flag before assuming
something else broke.

### `@s` vs `@u` (cross-session persistence)

A bare `keyctl padd ... @s` only lives for the current session
keyring. On a fresh SSH login, `_ses` is a new keyring and your key
is gone. Two ways to make the key survive across sessions for the
same UID:

```sh
# Option A: link an existing key into @u
keyctl link <KEYID> @u

# Option B: write directly into @u (makes the key "owned" by the user keyring)
keyctl padd user "elfdec:prod/myapp" @u < priv.bin
```

`elfdec-ssh-pushkey.sh` does Option A automatically (line 30 of the
script: `keyctl link "$KEYID" @u`) — that is why `ELFDEC_LABEL` works
from a *separate* SSH session after a single push, even though
`elfdec:prod/myapp` was added to the push-shell's `@s`.

`keypushd --link-user` (CLI flag in §6) is the same idea for the UDP
push path.

### When the keyring has no session at all

PAM with `pam_keyinit.so` (default on `login`, `gdm`, `sshd`) sets up
a fresh session keyring on each login. Headless / non-interactive
contexts that miss it:

| context | symptom | fix |
|---------|---------|-----|
| `cron`, `at` jobs | `keyctl_search: No such process` | call `keyctl new_session` first |
| `systemd` services without `User=` | keys land in `@u` for root, not `@s` | use `@u` directly |
| `docker run` (no `--privileged`) | `add_key: Operation not permitted` | run with `--cap-add SYS_ADMIN` or use Mode 4 (file-based) |
| `virtme-ng` test guests | session keyring is anonymous, padd-then-search across processes fails | known matrix-test caveat (see `tests/run_kernel_matrix.sh`) |
| `nspawn`, `chroot` w/o new session | inherits caller's `@s` (may surprise) | explicit `keyctl new_session` |

`elfdec-ssh-pushkey.sh` calls `keyctl new_session` on the remote side
(line 26: `keyctl new_session >/dev/null 2>&1 || true`) for exactly
this reason — without it, a non-interactive `ssh ... <command>`
invocation with `PermitTTY=no` may not have a usable `@s`.

### cgroup delegation (AC-03-09 environmental)

AC-03-09 needs `systemd-run --user --scope -p MemoryMax=...`, which
requires:

- `dbus-user-session` installed
- `pam_systemd` active in PAM (default on Ubuntu desktop / sshd)
- user cgroup delegation enabled

Quick check:

```sh
cat /sys/fs/cgroup/user.slice/user-$UID.slice/cgroup.controllers
# Should include "memory". If the file does not exist, you have no
# user cgroup at all — typical inside containers and on `su -`-style
# shells without a logind session.

systemctl --user status        # also a fast indicator: must say "running"
loginctl show-user $USER -p Linger
```

`elfdec-run` itself does not need any of this at runtime — only the
AC-03-09 *test* does.

### Distro package names cheat-sheet

| distro | core | optional (test only) |
|--------|------|----------------------|
| Ubuntu 22.04 / 24.04 | `build-essential libsodium-dev libkeyutils-dev` | `keyutils libssl-dev systemd-container` |
| Debian 12 | same | same |
| RHEL / Fedora / Alma 9 | `gcc make libsodium-devel keyutils-libs-devel` | `keyutils openssl-devel systemd-container` |
| Alpine | `build-base libsodium-dev keyutils-dev linux-headers` | `keyutils openssl-dev` |
| Arch | `base-devel libsodium keyutils` | (already in base) |

The runtime libraries are `libsodium23` (or `libsodium26`) and
`libkeyutils1`. A statically linked `elfdec-run` (`STATIC=1`) needs
none of these on the target.

### Useful one-liners from session debugging

```sh
# Decode keypushd bootstrap JSON without jq
SRV_PK=$(sed -E 's/.*"srv_pk":"([^"]+)".*/\1/' bootstrap.json)
TOKEN=$(sed  -E 's/.*"token":"([^"]+)".*/\1/'  bootstrap.json)

# Find leftover /dev/shm fallback artifacts (D-16 cleanup audit)
find /dev/shm -maxdepth 1 -name 'elfdec-*' -printf '%p (%s bytes)\n'

# What labels are currently in the session keyring (filter ephrun keys)
keyctl list @s | awk '/elfdec:|elfdec_caps:/'

# Force a fresh session keyring for one command (cron / nspawn)
keyctl session - bash -c 'keyctl padd user elfdec:prod/x @s < priv.bin'
```

## 8. What is validated

- **Linux end-to-end (`bash test.sh`):** the harness reports
  `Total: 47, Passed: 47` on a real host with logind + user cgroup
  delegation (Ubuntu / kernel 6.x). On a host where `systemd-run --user
  --scope` is unavailable (no DBus user bus, headless container, sshd
  with `pam_systemd` off), AC-03-09 fails and you see `Total: 47,
  Passed: 46` — that one is environmental, not an ephrun regression.
  Coverage: all four key-sourcing modes, capsule in keyring, KCAP3
  wire format, AC-03-04 / AC-03-05 D-16 fallback, AC-03-07 env scrub
  (memfd path + ETXTBSY fallback path), AC-03-08 D-19 LD_PRELOAD strip,
  AC-03-09 cgroup OOM (kernel-conditional per D-20), D-18 ptrace
  defense, plus negative tests (wrong code, corrupt ELFENC, missing
  key, wrong keypair).
- **Cross-platform (`make -C ephrun check`):** `kcap_kdf_test` ends
  with `ALL TESTS PASSED` (≈69 individual `ok:` assertions, range
  varies as cases are added). Covers: KCAP3 round-trip + fixture
  decrypt + AAD mutation rejection + D-15 floor/ceiling rejection +
  KCAP2/KCAP1 fixture decrypt + wrong code + Argon2id timing sanity +
  non-`KCAP` magic rejection. Linux and macOS produce identical
  results against the same fixture (AC-01-D-02 / AC-01-D-03).
- **Kernel matrix (`tests/run_kernel_matrix.sh`):** v5.15, v6.1, v6.5,
  v6.8 under virtme-ng. From `tests/KERNEL_MATRIX_REPORT.md`:

  | kernel | total | pass | fail | notes |
  |--------|------:|-----:|-----:|-------|
  | v5.4   |   —   |  —   |  —   | skipped: kernel image lacks virtio-serial |
  | v5.10  |   —   |  —   |  —   | skipped: kernel image lacks virtio-serial |
  | v5.15  |  47   | 43   |  4   | environmental baseline only |
  | v6.1   |  47   | 43   |  4   | environmental baseline only |
  | v6.5   |  47   | 43   |  4   | environmental baseline only |
  | v6.8   |  47   | 43   |  4   | environmental baseline only |

  The 4 failures are uniform across all completed kernels and are
  virtme-ng environmental limits (no logind for keyring sessions, no
  systemd-run for AC-03-09), not ephrun bugs. No kernel-version
  regression detected on the syscall surface ephrun relies on.
  AC-03-09(c) is kernel-conditional per D-20: pre-6.x kernels SIGKILL
  before `crypto_pwhash` returns ENOMEM, which the test treats as
  expected.

## 9. Troubleshooting

The error strings below are taken from `elfdec-run.c`'s `xdie` calls
(which append `: <strerror>` for the saved errno). The bracketed
errno hint is the libc translation you will see appended.

**`capsule decrypt failed (Cannot allocate memory)`**
Argon2id at M=64 MiB exceeded a cgroup memory ceiling. On kernels
< 6.x this typically arrives as a SIGKILL instead — the cgroup
OOM-killer fires before libsodium's `crypto_pwhash` can return
ENOMEM. Documented in D-20. Raise `MemoryMax` (cgroup) or remove
the limit; 96 MiB is the documented headroom that passes
`test.sh:617-630`.

**`capsule decrypt failed (Permission denied)`**
The AEAD verify failed — wrong `ELFDEC_CODE` or a tampered capsule.
Indistinguishable from "capsule corrupted" at this layer. Re-pack
the capsule from the original `priv.bin` on the builder.

**`capsule decrypt failed (Invalid argument)`**
The capsule failed structural validation before the KDF ran. Causes
include: wrong family magic, unknown `version` byte, non-zero
`flags` (reserved-must-be-zero per D-13 / AC-01-A-04), KDF params
outside the D-15 floor/ceiling range, or `ct_len` not matching the
buffer size. Re-pack with current `kcap_pack`.

**`refusing to run under tracer (TracerPid=N)`**
D-18 fired — `/proc/self/status` reported a non-zero `TracerPid`
(e.g. running under `strace`, `gdb -p`, or another `ptrace`
attach). For dev work set `ELFDEC_ALLOW_TRACE=1`; the variable
itself is in the D-17 scrub list and will not leak to the workload
(`test.sh:572-580`). Defeated by root via `/proc` manipulation —
this is bar-raising, not a security guarantee (`SECURITY.md` §4
item 7).

**`fexecve failed (Text file busy)` then a successful run**
Not actually a failure path the user sees — `elfdec-run` catches
`ETXTBSY` and falls through to the hardened `/dev/shm` route
(D-16): copy → open RO → close writer → unlink → `execveat
AT_EMPTY_PATH`. Workload runs from an inode with zero filesystem
references. Any other `fexecve` errno (ENOEXEC, EACCES, ...) is
fatal — no plaintext is written to `/dev/shm`. On kernels < 3.19,
`execveat` is `ENOSYS` and the fallback fails closed.

**`open /dev/shm/elfdec-NNN: File exists`**
A previous `elfdec-run` crashed before unlink. Safe to remove
manually: `rm -f /dev/shm/elfdec-*`. The `O_EXCL` open is a TOCTOU
mitigation, not a leak — there is nothing readable in those files
unless a crash hit before the unlink.

**`no private key available`**
None of the four key-sourcing tiers found anything. Diagnostic
checklist:
- `ELFDEC_CODE` set but no capsule? `elfdec-run` prints
  `warning: ELFDEC_CODE set but no capsule found (keyring or
  <path>/{capsule.bin,capsule.json})`. Verify
  `$ELFDEC_KEYPATH/capsule.bin` exists or the keyring entry
  `elfdec_caps:<ELFDEC_LABEL>` is present.
- `ELFDEC_KEYID` invalid prints `warning: invalid ELFDEC_KEYID
  '<value>'` or `warning: ELFDEC_KEYID read failed: <reason>`.
- File mode wrong on `priv.bin`? `elfdec-run` prints `open <path>:
  Permission denied`. Check `chmod 600`.

**Workload sees `ELFDEC_*` or `LD_PRELOAD` in `/proc/self/environ`**
Diagnostic for "is the env scrub working?". The expected answer is
**no** — D-17 strips `ELFDEC_CODE / KEYID / LABEL / KEYPATH / CAP /
ALLOW_TRACE`, D-19 strips `LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT
/ LD_DEBUG / LD_PROFILE / GCONV_PATH / HOSTALIASES / LOCPATH /
NLSPATH / DYLD_INSERT_LIBRARIES / DYLD_LIBRARY_PATH / BASH_ENV /
ENV / NODE_OPTIONS / PYTHONSTARTUP / PERL5OPT / PERL5LIB / RUBYOPT
/ RUBYLIB / _JAVA_OPTIONS / JAVA_TOOL_OPTIONS / CDPATH /
GLOBIGNORE` from the workload's envp (`elfdec-run.c:151-186`). If
any of these appear in the workload, you are running an outdated
`elfdec-run` — rebuild from current source. PATH and other
unrelated variables pass through (`test.sh:365-369`).

**`bad magic`**
The `.elfenc` file's first 8 bytes are not `ELFENC1\0`. The file
is corrupt, truncated, or never went through `elfenc_pack`. Re-encrypt.

**`fexecve failed (Exec format error)`**
The plaintext that came out of `crypto_box_seal_open` is not a
valid ELF for the host architecture. Either the source binary was
built for a different architecture, or the wrong `pub.bin` was
used to encrypt (the decrypt verified but produced garbage —
unlikely with sealed boxes, possible if you mixed up keys). Verify
with `file hello && ./elfenc_pack pub.bin hello hello.elfenc`
on the builder using a host-matching binary.

**`/lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.NN' not found`**
The dynamic `elfdec-run` was built against a newer glibc than the
target has. Common when shipping from Ubuntu 24.04 (glibc 2.39) to
22.04 (glibc 2.35) or older. Rebuild with `make -C ephrun STATIC=1`
and ship the static binary; same fix applies if the host is missing
`libsodium23` / `libkeyutils1` entirely.

**`add_key: Operation not permitted` (in containers)**
A rootless / unprivileged container cannot add keys to its session
keyring. Either grant `--cap-add SYS_ADMIN` to the container, run
the container with `--privileged`, or fall back to Mode 4 (file-based)
which does not need the keyring at all.

**`keyctl_search ... No such process` (in cron / at / systemd)**
The job has no session keyring because no PAM session was set up.
Wrap the command in `keyctl session - <command>` (creates a fresh
session keyring scoped to the child) or call `keyctl new_session`
before the keyctl operations. See §7 "When the keyring has no
session at all".

**`keyctl padd ... Disk quota exceeded`**
The kernel's per-user keyring quota (`/proc/sys/kernel/keys/maxbytes`,
`/proc/sys/kernel/keys/maxkeys`) is full. Usually the result of a
long-running daemon leaking key links. `keyctl list @u` to see what
accumulated; `keyctl unlink` or `keyctl revoke` the dead ones. The
defaults (200 keys, 20000 bytes per UID) are tight on shared hosts.

**Build failures.**
- `fatal error: sodium.h: No such file or directory` — install
  `libsodium-dev`.
- `fatal error: keyutils.h: No such file or directory` — install
  `libkeyutils-dev`. On RHEL / Fedora the package is
  `keyutils-libs-devel`.
- `cannot find -lkeyutils` at link time — same package missing.
- `make` finishes but `kcap_unpack` is missing — you are on a top-level
  Makefile from before the kcap_unpack target was added; either
  `git pull` or run `make -C ephrun kcap_unpack` directly.

## 10. What is NOT in this guide

- **Threat model details** — `SECURITY.md` is the authoritative source
  for what the system protects against and what it does not.
- **Wire formats** — `SPEC.md` §"Wire formats" for ELFENC1, KCAP3,
  KCAP2, KCAP1.
- **Architectural rationale per decision** — `DECISIONS.md` D-1
  through D-20.
