# Docker Deployment Guide

Running encrypted binaries in Docker containers on untrusted cloud infrastructure.

## Why?

When you deploy to a cloud VM, the provider can snapshot the disk at any time.
ephrun ensures that a snapshot captures only encrypted artifacts — the cleartext
binary and private key never exist as files.

```
What a snapshot captures:          What an attacker gets:
  myapp.elfenc                       encrypted blob (useless)
  capsule.bin                        encrypted key (useless without code)
  elfdec-run                         the runner (public tool)
```

The decryption code (`ELFDEC_CODE`) lives only in process memory at runtime —
injected via environment variable from an external secrets manager.

---

## Pattern A: Capsule (Recommended)

Best for most deployments. The encrypted capsule is baked into the image,
and the unlock code is injected at runtime.

### Threat model

| Threat | Protected? |
|--------|------------|
| Disk/image snapshot | Yes — only encrypted files |
| Image theft (registry breach) | Yes — `.elfenc` + `capsule.bin` are useless without code |
| Container filesystem escape | Yes — no cleartext keys on disk |
| Live hypervisor RAM dump | No — fundamental limit of untrusted infrastructure |

### Build (on your trusted machine)

```bash
cd ephrun

# 1. Generate keypair
./genkey                    # creates pub.bin + priv.bin

# 2. Encrypt your binary
./elfenc_pack pub.bin myapp myapp.elfenc

# 3. Create capsule (wraps priv.bin with a secret code)
#    Use a strong random code, not a password:
CODE=$(head -c 16 /dev/urandom | base64)
echo "Save this code securely: $CODE"
./kcap_pack --label prod/myapp --code "$CODE" --in priv.bin --out capsule.bin

# 4. Store CODE in your secrets manager (Vault, AWS SM, etc.)
#    Delete priv.bin from this machine if desired — capsule.bin is the key now.
```

### Dockerfile (production)

For production, do NOT generate keys inside Docker — copy pre-built artifacts:

```dockerfile
FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends libsodium23 libkeyutils1 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /usr/sbin/nologin appuser

# Copy pre-built artifacts from your trusted build machine
COPY elfdec-run    /usr/local/bin/elfdec-run
COPY myapp.elfenc  /app/myapp.elfenc
COPY capsule.bin   /app/capsule.bin

RUN chmod 0755 /usr/local/bin/elfdec-run && \
    chown -R appuser:appuser /app

USER appuser
WORKDIR /app
ENV ELFDEC_KEYPATH=/app

ENTRYPOINT ["/usr/local/bin/elfdec-run"]
CMD ["/app/myapp.elfenc"]
```

### Run

```bash
# Direct — code from environment
docker run -e ELFDEC_CODE="$CODE" myapp-encrypted

# With Vault
docker run -e ELFDEC_CODE="$(vault read -field=code secret/myapp)" myapp-encrypted

# With AWS Secrets Manager
docker run -e ELFDEC_CODE="$(aws secretsmanager get-secret-value \
    --secret-id myapp/elfdec-code --query SecretString --output text)" \
    myapp-encrypted

# With Docker secrets (Swarm)
echo "$CODE" | docker secret create elfdec_code -
docker service create --secret elfdec_code \
    -e ELFDEC_CODE_FILE=/run/secrets/elfdec_code myapp-encrypted
```

### Demo (self-contained)

The included `Dockerfile` generates keys inside the build for demo purposes:

```bash
# Build demo image (generates keys inside Docker — NOT for production)
docker build -t ephrun-demo -f docker/Dockerfile .

# Run with the demo code
docker run -e ELFDEC_CODE=demo-secret-change-me ephrun-demo

# Expected output:
# hello from encrypted ELF!
# argv[0]=/app/hello.elfenc
```

### docker compose

```bash
ELFDEC_CODE=demo-secret-change-me docker compose -f docker/docker-compose.yml up capsule
```

---

## Pattern B: keypushd (No Secrets in Image)

Most paranoid option. The Docker image contains zero key material — not even
an encrypted capsule. The key is delivered at runtime over UDP, goes directly
into the kernel keyring, and never touches disk.

### Threat model

| Threat | Protected? |
|--------|------------|
| Disk/image snapshot | Yes — no key material at all in image |
| Image theft | Yes — nothing secret to steal |
| Network MITM | Yes — sealed box encryption with ephemeral keypair |
| Container filesystem escape | Yes — key in kernel keyring only |
| Live hypervisor RAM dump | No — fundamental limit |

### How it works

```
┌─────────────────────────┐                    ┌──────────────────┐
│  Docker container       │                    │  Control machine  │
│                         │                    │  (trusted)        │
│  1. keypushd starts     │                    │                   │
│  2. prints bootstrap    │─── JSON stdout ──▶ │  operator sees:   │
│     {srv_pk, token,     │                    │  srv_pk + token   │
│      port, expires}     │                    │                   │
│                         │                    │  3. keypush_send   │
│  4. receives sealed key │◀── UDP sealed ──── │     sends priv.bin│
│  5. key → keyring       │    box             │                   │
│  6. exec elfdec-run     │                    │                   │
│     (decrypts+runs)     │                    │                   │
└─────────────────────────┘                    └──────────────────┘
```

### Build

```bash
docker build -t myapp-keypushd -f docker/Dockerfile.keypushd .
```

### Run

```bash
# Terminal 1: Start container (prints bootstrap JSON)
docker run -p 9999:9999/udp myapp-keypushd

# Output:
# === keypushd starting ===
# Waiting for key delivery on 0.0.0.0:9999/udp
# Label: prod/myapp  TTL: 300s
#
# {"ip":"0.0.0.0","port":9999,"srv_pk":"xK7b+...","token":"ABC123...","expires":1706500000}

# Terminal 2: Send the key from your trusted machine
cat priv.bin | ./keypush_send \
    --ip 127.0.0.1 --port 9999 \
    --srv-pk-b64 "xK7b+..." \
    --token "ABC123..." \
    --label prod/myapp --ttl 300 --wait-ack

# Terminal 1 continues:
# === Key received — executing encrypted binary ===
# hello from encrypted ELF!
```

### docker compose

```bash
docker compose -f docker/docker-compose.yml up keypushd

# Then send the key from another terminal using the bootstrap JSON
```

---

## Kubernetes Integration

### Capsule pattern with K8s secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: elfdec-code
type: Opaque
data:
  code: <base64-encoded-ELFDEC_CODE>
---
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
  - name: myapp
    image: myregistry/myapp-encrypted:latest
    env:
    - name: ELFDEC_CODE
      valueFrom:
        secretKeyRef:
          name: elfdec-code
          key: code
    securityContext:
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      allowPrivilegeEscalation: false
```

### With external secrets operator (Vault, AWS SM)

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: elfdec-code
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: elfdec-code
  data:
  - secretKey: code
    remoteRef:
      key: secret/data/myapp
      property: elfdec_code
```

---

## Security Hardening Checklist

- [ ] Use multi-stage builds — build tools don't ship in runtime image
- [ ] Run as non-root user (`USER appuser`)
- [ ] Read-only root filesystem (`read_only: true`)
- [ ] No new privileges (`no-new-privileges:true`)
- [ ] `ELFDEC_CODE` from external secrets manager, never hardcoded
- [ ] Use capsule TTL (`--ttl 86400`) to limit key validity window
- [ ] Use strong random codes: `head -c 16 /dev/urandom | base64`
- [ ] Scan image for accidentally included key files (`priv.bin`, `pub.bin`)
- [ ] Consider `--tmpfs /tmp:noexec,nosuid` to prevent temp file attacks
- [ ] For keypushd: restrict UDP port access via network policy

## Troubleshooting

### "memfd_create: Operation not permitted"

Some hardened Docker/K8s setups block `memfd_create` via seccomp. Fix:

```bash
# Docker
docker run --security-opt seccomp=unconfined ...

# Or create a custom seccomp profile that allows memfd_create
```

### "keyctl_search: Permission denied"

Kernel keyring requires `CAP_SYS_ADMIN` in some configurations:

```bash
docker run --cap-add SYS_ADMIN ...
```

Note: This is typically only needed for keypushd pattern. Capsule pattern
(Mode 1) doesn't require keyring access.

### "capsule decrypt failed (Permission denied)"

Capsule TTL has expired. Create a new capsule with a longer TTL or
without TTL (`--ttl 0`).

### Container exits immediately

Check that `ELFDEC_CODE` is set:

```bash
docker run -e ELFDEC_CODE="your-code" myimage
# NOT: docker run myimage  (code is empty, capsule decrypt fails)
```
