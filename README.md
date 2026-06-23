# ephrun — Encrypted ELF Execution System

Encrypted binary distribution and execution system for Linux using X25519 + XSalsa20-Poly1305 (libsodium sealed boxes), Linux kernel keyring for key storage, and memfd-based in-memory execution.

## Threat Model — Short Version

ephrun protects encrypted artifacts at rest and raises the extraction bar on
untrusted Linux hosts. It is **not** a DRM system and does **not** defend a
running workload against a hostile root user, compromised kernel, ptrace-capable
attacker, process-memory scraping, live runtime instrumentation, or a loader
attack that affects a dynamically linked `elfdec-run` before `main()` starts
(`STATIC=1` is the deployment hardening path for that case). See
`SECURITY.md` for the full threat model.

## Architecture

```
genkey          → pub.bin + priv.bin   (X25519 keypair)
elfenc_pack     → .elfenc file         (sealed encrypted ELF)
kcap_pack       → capsule.bin          (KCAP3 code-protected key wrapper)
kcap_unpack     → capsule.bin → priv   (cross-platform CLI unwrap, for tooling)
elfdec-run      → executes .elfenc     (decrypt + memfd + fexecve, Linux only)

Key distribution:
  add_keyring*.sh        → local keyring injection
  elfdec-ssh-pushkey.sh  → remote via SSH
  keypushd / keypush_send → remote via UDP sealed box
```

## Directory Structure

```
ephrun/           Core encryption/decryption tools
keypush/             UDP key distribution (daemon + sender)
```

---

## Quick Start

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install -y build-essential libsodium-dev libkeyutils-dev

# Build everything (top-level Makefile)
make                            # builds core tools + keypush

# Or build from ephrun/ directory
cd ephrun
make                            # builds all tools for this platform
make STATIC=1                   # static linking (for deployment to remote machines)

# Generate keypair
./genkey                        # creates pub.bin + priv.bin

# Build and encrypt a test binary
gcc -O2 hello.c -o hello
./elfenc_pack pub.bin hello hello.elfenc

# Run it (simplest mode — file-based keys)
mkdir -p ~/.elfenc
cp pub.bin priv.bin ~/.elfenc/
chmod 600 ~/.elfenc/priv.bin
./elfdec-run ./hello.elfenc     # → "hello from encrypted ELF!"
```

---

## The 4 Key Sourcing Modes

`elfdec-run` tries to obtain the private key in this priority order.
The first one that succeeds is used; the rest are skipped.

```
Priority 1:  ELFDEC_CODE     → capsule (code-protected key)
Priority 2:  ELFDEC_KEYID    → keyring by numeric key ID
Priority 3:  ELFDEC_LABEL    → keyring by label search
Priority 4:  ELFDEC_KEYPATH  → file-based (priv.bin + pub.bin)
     or:     ~/.elfenc/       → default file fallback
```

---

### Mode 1 — Capsule (ELFDEC_CODE)

A capsule wraps the private key with a password/code. The raw `priv.bin`
never touches the target disk — only the encrypted capsule is deployed.
At runtime, `elfdec-run` decrypts the capsule in memory using the code.

**Crypto:** XChaCha20-Poly1305 AEAD with Argon2id (M=64 MiB, T=3, P=1 by default) key derivation — `K = Argon2id(code, salt)`.

> **Format versions:** New capsules use the `KCAP3` format (family magic `KCAP` +
> version byte + project_id + AAD-bound 64-byte header; Argon2id parameters live
> in the header so future tuning isn't a wire-format break). Legacy `KCAP2`
> (Argon2id, fixed params) and `KCAP1` (single-pass SHA256) capsules are still
> readable by `elfdec-run` for migration, but should be rotated — re-run
> `kcap_pack` against the original `priv.bin` to produce a `KCAP3` capsule and
> deploy the new file. The capsule format is dispatched by the magic bytes, so
> old capsules keep working until you replace them.

**How it works:**

```
  ┌──────────────┐
  │   kcap_pack   │   priv.bin + --code "mysecret"
  │   (build-time)│ ──────────────────────────────────▶ capsule.bin
  └──────────────┘                                     (encrypted priv key)
                                                           │
       deploy capsule.bin to target                        │
       (safe — encrypted, can't be used without code)      ▼
                                                     ┌──────────────┐
                                                     │  elfdec-run   │
       ELFDEC_CODE="mysecret"  ─────────────────────▶│  (runtime)    │
                                                     │  1. finds capsule
                                                     │  2. derives K from code
                                                     │  3. decrypts → priv key
                                                     │  4. decrypts .elfenc
                                                     │  5. executes via memfd
                                                     └──────────────┘
```

**Step-by-step example:**

```bash
# ── BUILD TIME (on trusted machine) ──

# 1. Generate keypair
./genkey                    # → pub.bin, priv.bin

# 2. Encrypt your binary
./elfenc_pack pub.bin myapp myapp.elfenc

# 3. Create a capsule (wraps priv.bin with a code)
gcc -O2 kcap_pack.c -lsodium -o kcap_pack

# KCAP3 binary capsule (the only output format kcap_pack writes today):
./kcap_pack --label prod/myapp --code "s3cret-C0de" --in priv.bin --out capsule.bin

# `--json` is deprecated and prints a warning; KCAP3 is binary-only.
# `--ttl` is also deprecated (TTL was a KCAP2 wrapper concern).

# 4. Deploy to target: myapp.elfenc + capsule.bin (priv.bin stays here — never deployed)

# ── RUNTIME (on target machine) ──

# Option A: capsule on disk via ELFDEC_KEYPATH
mkdir -p /opt/myapp/keys
cp capsule.bin /opt/myapp/keys/     # elfdec-run looks for capsule.bin (or legacy capsule.json) here
ELFDEC_CODE="s3cret-C0de" ELFDEC_KEYPATH=/opt/myapp/keys ./elfdec-run ./myapp.elfenc

# Option B: capsule stored in kernel keyring (no disk file needed)
keyctl padd user "elfdec_caps:prod/myapp" @s < capsule.bin
ELFDEC_CODE="s3cret-C0de" ELFDEC_LABEL="prod/myapp" ./elfdec-run ./myapp.elfenc
#                                                     ▲
#                    searches keyring for "elfdec_caps:prod/myapp", decrypts with code
```

**Capsule lookup order in elfdec-run:**
1. Keyring: searches `@s` then `@u` for key named `elfdec_caps:<ELFDEC_LABEL>`
2. File: `$ELFDEC_KEYPATH/capsule.bin` then `$ELFDEC_KEYPATH/capsule.json`

---

### Mode 2 — Keyring by ID (ELFDEC_KEYID)

Use when you know the exact numeric key ID (e.g. returned by `keyctl padd` or `keypushd`).

```bash
# Inject the raw private key into the session keyring
KEYID=$(keyctl padd user "elfdec:prod/myapp" @s < priv.bin)
keyctl setperm "$KEYID" 0x3f030000    # owner: view+read, possessor: all
keyctl timeout "$KEYID" 300            # auto-expire in 5 minutes

# Run using the numeric key ID
ELFDEC_KEYID="$KEYID" ./elfdec-run ./myapp.elfenc
```

---

### Mode 3 — Keyring by Label (ELFDEC_LABEL)

Use when the key is in the keyring with a known label. `elfdec-run` searches
for a key named `elfdec:<ELFDEC_LABEL>` in `@s` (session) then `@u` (user).

```bash
# Inject key with label
keyctl padd user "elfdec:prod/myapp" @s < priv.bin
keyctl setperm "$(keyctl search @s user 'elfdec:prod/myapp')" 0x3f030000

# Run using label — elfdec-run searches for "elfdec:prod/myapp"
ELFDEC_LABEL="prod/myapp" ./elfdec-run ./myapp.elfenc

# If ELFDEC_LABEL is unset, the .elfenc file path is used as the label
./elfdec-run ./myapp.elfenc   # searches for "elfdec:<realpath of myapp.elfenc>"
```

**Helper scripts for keyring injection:**
- `add_keyring4.sh` — Full-featured: root/user detection, permission fallback loop, accessibility test
- `add_keyring8.sh` — Concise production version: session keyring, perms, TTL, `@u` link

---

### Mode 4 — File-based (ELFDEC_KEYPATH or ~/.elfenc/)

Simplest mode. Only `priv.bin` is needed on disk — the public key is derived
automatically via `crypto_scalarmult_base()`. Protect with filesystem permissions.

```bash
# Custom key directory
sudo mkdir -p /etc/elfenc
sudo cp priv.bin /etc/elfenc/
sudo chmod 600 /etc/elfenc/priv.bin

ELFDEC_KEYPATH=/etc/elfenc ./elfdec-run ./myapp.elfenc

# Default directory (~/.elfenc/) — no env vars needed
mkdir -p ~/.elfenc
cp priv.bin ~/.elfenc/
chmod 600 ~/.elfenc/priv.bin

./elfdec-run ./myapp.elfenc     # automatically finds ~/.elfenc/priv.bin, derives pub
```

> **Note:** `pub.bin` is still needed by `elfenc_pack` at build time (encryption).
> At runtime, `elfdec-run` only needs `priv.bin` — it derives the public key.

---

## Environment Variables Reference

| Variable | Used By | Description |
|----------|---------|-------------|
| `ELFDEC_CODE` | elfdec-run | Password/code to decrypt a capsule (triggers Mode 1) |
| `ELFDEC_KEYID` | elfdec-run | Numeric key ID from kernel keyring (Mode 2) |
| `ELFDEC_LABEL` | elfdec-run | Key label for keyring search + capsule lookup (Mode 3 / Mode 1) |
| `ELFDEC_KEYPATH` | elfdec-run | Directory containing `{priv,pub}.bin` or `capsule.{bin,json}` (Mode 4 / Mode 1) |

---

## Key Distribution Methods

### Local: add_keyring scripts

```bash
# Full-featured (detects root vs user, tries multiple permission masks)
bash add_keyring4.sh

# Concise production version
bash add_keyring8.sh
```

### Remote via SSH: elfdec-ssh-pushkey.sh

Streams the raw key bytes over SSH stdin into the remote kernel keyring.
The key never touches the remote disk.

```bash
# Push key to remote host (default TTL: 300s)
./elfdec-ssh-pushkey.sh -H user@remote -l prod/myapp -k priv.bin

# With custom TTL
./elfdec-ssh-pushkey.sh -H user@remote -l prod/myapp -k priv.bin -t 600

# Returns KEYID — use it on the remote machine:
# ELFDEC_KEYID=<returned_id> /usr/local/bin/elfdec-run ./myapp.elfenc
```

### Remote via UDP: keypushd + keypush_send

For automated/programmatic key distribution over the network.

**Protocol flow:**

```
 ┌─────────────┐                           ┌─────────────┐
 │  keypushd    │  1. prints bootstrap JSON │  operator    │
 │  (target)    │ ◀─── stdout ────────────▶ │  (control)   │
 │              │     {ip, port, srv_pk,    │              │
 │              │      token, expires}      │              │
 │              │                           │              │
 │              │  2. sealed UDP datagram   │ keypush_send │
 │  recvfrom()  │ ◀──── network ─────────── │  (sender)    │
 │              │     crypto_box_seal(      │              │
 │              │       {label, ttl, token, │              │
 │              │        key_b64})          │              │
 │              │                           │              │
 │  add_key()   │  3. ACK/NAK JSON reply   │              │
 │  keyring @s  │ ─────── UDP ──────────▶   │              │
 └─────────────┘     {ok, keyid, ttl}       └─────────────┘
```

**The `srv_pk` (server public key) is NOT pre-generated** — keypushd creates an ephemeral
X25519 keypair on every launch and prints the public key as base64 in the bootstrap JSON.
The operator copies `srv_pk` and `token` to the sender side (out-of-band: terminal, pipe, etc.).

```bash
# Build (both keypushd + keypush_send from the same directory)
cd keypush && make

# ── Step 1: Start the daemon on the TARGET machine ──
./keypushd --bind 0.0.0.0 --port 9999 --label prod/myapp --ttl 300

# Output (example):
# {"ip":"0.0.0.0","port":9999,"srv_pk":"xK7b+...BASE64...","token":"K3J7QRST...","expires":1706500000}
#                                  ▲                             ▲
#                                  │                             │
#                    ephemeral pubkey (base64)          one-time auth token (base32)
#                    copy this to --srv-pk-b64          copy this to --token

# Full example with all options:
./keypushd --bind 10.8.0.2 --port 0 --label prod/myapp --ttl 600 --window 120 --link-user --detach
#                           ▲ port=0 picks a random free port     ▲ window = bootstrap expiry (seconds)

# ── Step 2: Send the key FROM the control machine ──
cat priv.bin | ./keypush_send \
    --ip 10.8.0.2 --port 9999 \
    --srv-pk-b64 "xK7b+...BASE64..." \
    --token "K3J7QRST..." \
    --label prod/myapp --ttl 300 --wait-ack

# Output (if --wait-ack): {"ok":true,"keyid":827867509,"ttl":300}

# ── Step 3: Run on the TARGET machine ──
ELFDEC_LABEL="prod/myapp" ./elfdec-run ./myapp.elfenc
```

**keypushd CLI options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--bind IP` | *(required)* | IP address to bind UDP socket |
| `--port N` | `0` (random) | UDP port; 0 = OS picks a free port |
| `--label L` | *(from payload)* | Default label if sender omits it |
| `--ttl N` | `300` | Max key TTL in seconds |
| `--window N` | `60` | Seconds before the bootstrap token expires |
| `--detach` | off | Fork to background after printing bootstrap JSON |
| `--link-user` | off | Also link key into `@u` (user keyring) for persistence |

**keypush_send CLI options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--ip IP` | *(required)* | Target keypushd IP address |
| `--port N` | *(required)* | Target keypushd UDP port |
| `--srv-pk-b64 B64` | *(required)* | Server public key (base64 from bootstrap JSON `srv_pk` field) |
| `--token T` | *(required)* | Auth token (base32 from bootstrap JSON `token` field) |
| `--label L` | *(required)* | Key label (e.g. `prod/myapp`) |
| `--ttl N` | `300` | Requested key TTL in seconds (server caps it at its `--ttl` max) |
| `--wait-ack` | off | Wait up to 3s for ACK/NAK JSON reply |

---

## binfmt_misc — Transparent .elfenc Execution

Register the ELFENC1 magic with the kernel so `.elfenc` files can be executed directly:

```bash
sudo bash register_elfenc.sh

# Now .elfenc files work like regular executables:
chmod +x myapp.elfenc
ELFDEC_LABEL="prod/myapp" ./myapp.elfenc
```

---

## File Reference

### Core Tools

| File | Build | Description |
|------|-------|-------------|
| `ephrun/genkey.c` | `gcc -O2 genkey.c -lsodium -o genkey` | Generate X25519 keypair (pub.bin + priv.bin) |
| `ephrun/elfenc_pack.c` | `gcc -O2 elfenc_pack.c -lsodium -o elfenc_pack` | Encrypt ELF → ELFENC1 format |
| `ephrun/kcap_pack.c` | `gcc -O2 kcap_pack.c -lsodium -o kcap_pack` | Create KCAP3 capsules (Argon2id-wrapped key, params in header) |
| `ephrun/kcap_unpack.c` | `gcc -O2 kcap_unpack.c -lsodium -o kcap_unpack` | Cross-platform CLI: unwrap KCAP1/KCAP2/KCAP3 → priv key (for tooling/CI) |
| `ephrun/elfdec-run.c` | `gcc -O2 -D_GNU_SOURCE elfdec-run.c -lsodium -lkeyutils -o elfdec-run` | Decrypt + execute .elfenc (4-tier key sourcing; D-16 hardened fallback, D-17 env scrub, D-18 ptrace check) |
| `ephrun/hello.c` | `gcc -O2 hello.c -o hello` | Minimal test binary for the pipeline |

### Libraries / Headers

| File | Description |
|------|-------------|
| `ephrun/kcap.h` | Shared KCAP capsule header (KCAP1/KCAP2/KCAP3 dispatch, Argon2id + legacy SHA256 KDF, D-15 param policy floor/ceiling) |
| `ephrun/libexec_key.h` | Header-only key loading library (file, keyring, env, capsule) |

### Key Distribution

| File | Description |
|------|-------------|
| `ephrun/add_keyring4.sh` | Full-featured local keyring setup (root/user, perm fallback, test) |
| `ephrun/add_keyring8.sh` | Concise production keyring setup |
| `ephrun/elfdec-ssh-pushkey.sh` | Push key to remote host via SSH stdin |
| `keypush/keypushd.c` | UDP key receiver daemon (Linux only) |
| `keypush/keypush_send.c` | UDP key sender (cross-platform: Linux + macOS) |

### Testing & Diagnostics

| File | Build | Description |
|------|-------|-------------|
| `test.sh` | `bash test.sh` | **Full end-to-end test suite** — builds all tools, tests all 4 key modes, negative tests |
| `ephrun/test_key.c` | `gcc -O2 test_key.c -lkeyutils -o test_key` | Verify a key exists in the keyring |
| `ephrun/keyring_selftest.c` | `gcc -O2 -D_GNU_SOURCE keyring_selftest.c -lsodium -lkeyutils -o keyring_selftest` | Self-test: keyring add/read + crypto_secretbox roundtrip |
| `ephrun/keyring_crypto_test.c` | `make` (in ephrun/) | AES-256-CBC roundtrip with keyring-sourced key (OpenSSL) |

### Helper Scripts

| File | Description |
|------|-------------|
| `ephrun/install.sh` | Full install: deps + build + keygen + test encrypt/run |
| `ephrun/elf_comp.sh` | Compile elfdec-run + install keys to /etc/elfenc |
| `ephrun/genkey.sh` | Compile + run genkey in one step |
| `ephrun/run.sh` | Test script: KEYID and LABEL execution modes |
| `ephrun/register_elfenc.sh` | Register .elfenc with binfmt_misc |

---

## Dependencies

| Package | Used by | Purpose |
|---------|---------|---------|
| `libsodium-dev` | all C programs | X25519, XSalsa20-Poly1305, XChaCha20, SHA256 |
| `libkeyutils-dev` | elfdec-run, keypushd, tests | Linux kernel keyring API |
| `libssl-dev` | keyring_crypto_test only | OpenSSL EVP (AES-256-CBC) |
| `build-essential` | all | GCC toolchain |

```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential libsodium-dev libkeyutils-dev libssl-dev

# RHEL/CentOS/Fedora
sudo yum install -y keyutils-libs-devel libsodium-devel gcc openssl-devel

# macOS (keypush_send only — keypushd and elfdec-run require Linux keyring)
brew install libsodium
```

## Security Features

- **Transport:** X25519 + XSalsa20-Poly1305 authenticated encryption (sealed boxes)
- **Key storage:** Linux kernel keyring (memory-protected, process-isolated, TTL support)
- **Execution:** Sealed memfd (MFD_EXEC + F_SEAL_SHRINK/GROW/WRITE) — on the normal path, plaintext never touches a filesystem path
- **Process hardening:** PR_SET_DUMPABLE=0, PR_SET_NO_NEW_PRIVS=1
- **Memory safety:** sodium_memzero on all sensitive data, sodium_mlock on decrypted capsule keys
- **Capsule encryption:** XChaCha20-Poly1305 AEAD with Argon2id key derivation; KCAP3 stores T/M/P in the header (default T=3, M=64 MiB, P=1) and AAD-binds the entire 64-byte header. KCAP2 (Argon2id, fixed params) and KCAP1 (SHA256 KDF) remain readable for migration.
- **Build hardening:** -fstack-protector-strong, -D_FORTIFY_SOURCE=2, -Wl,-z,relro,-z,now
- **Core dumps disabled:** RLIMIT_CORE set to zero in keypushd; PR_SET_DUMPABLE=0 in elfdec-run
- **Portable binary formats:** ELFENC1, KCAP1, KCAP2, KCAP3 use explicit little-endian encoding for cross-architecture compatibility
- **`/dev/shm` fallback hardening (D-16):** triggers only on `fexecve` ETXTBSY; the temp file is unlinked before `execveat(rofd, "", argv, envp, AT_EMPTY_PATH)` so the workload runs from an unreachable inode; on exec failure the inode is wiped via `/proc/self/fd/N`. O_EXCL guards the brief tmpfs creation window. Requires Linux ≥ 3.19.
- **Env scrub (D-17):** `elfdec-run` strips `ELFDEC_CODE / KEYID / LABEL / KEYPATH / CAP / ALLOW_TRACE` from `envp` before any `fexecve` / `execveat`, so the workload's `/proc/<pid>/environ` does not leak the unwrap inputs.
- **Ptrace defense (D-18):** `elfdec-run` reads `/proc/self/status` at startup and aborts before any decryption work if `TracerPid != 0`. `ELFDEC_ALLOW_TRACE=1` bypasses for dev. Defeated by root via `/proc` manipulation; this is bar-raising, not a security guarantee.

## Detecting Docker / VM Environments

When deploying to rented servers, it's important to know whether you're running
in a container (weaker isolation) or a real VM. ephrun protects the binary on
disk, but a Docker host with root access can inspect process memory.

```bash
# Quick checks — run any/all of these on the target machine:

# 1. Docker sentinel file (most reliable)
ls -la /.dockerenv 2>/dev/null && echo "DOCKER" || echo "not docker (by sentinel)"

# 2. Cgroup — look for "docker" or "containerd" in cgroup paths
cat /proc/1/cgroup 2>/dev/null | grep -qiE 'docker|containerd' && echo "DOCKER" || echo "not docker (by cgroup)"

# 3. systemd-detect-virt (if installed)
#    Returns "docker", "lxc", "kvm", "vmware", "xen", "none", etc.
systemd-detect-virt 2>/dev/null || echo "(not installed)"

# 4. Container-specific mounts
mount | grep -q 'overlay' && echo "likely container (overlay fs)"

# 5. PID 1 — in a container it's usually NOT systemd/init
cat /proc/1/cmdline | tr '\0' ' ' | head -c 200
# systemd or /sbin/init → real VM;  /bin/sh or custom entrypoint → container

# 6. DMI / product name (VMs expose hypervisor info)
cat /sys/class/dmi/id/product_name 2>/dev/null
# "QEMU", "VMware Virtual Platform", "VirtualBox", etc. → real VM
# empty or permission denied → possibly container

# 7. Kernel keyring — containers often have restricted keyring access
keyctl show @s 2>/dev/null && echo "keyring OK" || echo "keyring restricted (container?)"
```

**Summary:**
- Container (Docker/LXC): host has root over your processes — use short key TTLs, push keys just before execution, minimize execution windows
- Real VM (KVM/QEMU/VMware): stronger isolation — host can still snapshot RAM, but needs memory forensics to extract anything
- Neither is bulletproof on hardware you don't own; ephrun raises the bar from "copy a file" to "live memory forensics"

---

## Development note

This project was AI-assisted — though in 2026, what isn't? Design, code, and
release decisions remain maintainer-owned.
