# ============================================================================
# Dockerfile — Capsule pattern (Mode 1)
#
# The image contains only encrypted artifacts:
#   - myapp.elfenc     (encrypted binary)
#   - capsule.bin      (encrypted private key)
#   - elfdec-run       (the runner)
#
# At runtime, ELFDEC_CODE is injected via environment variable.
# A VM/disk snapshot captures nothing useful — all encrypted.
#
# Build:
#   docker build -t myapp-encrypted -f docker/Dockerfile .
#
# Run:
#   docker run -e ELFDEC_CODE="your-secret-code" myapp-encrypted
# ============================================================================

# ── Stage 1: Build tools ──
FROM ubuntu:24.04 AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential libsodium-dev libkeyutils-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY ephrun/elfdec-run.c ephrun/elfenc_pack.c ephrun/kcap_pack.c \
     ephrun/genkey.c ephrun/hello.c ./

# Build all tools
RUN gcc -O2 -Wall -Wextra -D_GNU_SOURCE \
        -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
        elfdec-run.c -lsodium -lkeyutils -Wl,-z,relro,-z,now \
        -o elfdec-run && \
    gcc -O2 -Wall -Wextra \
        elfenc_pack.c -lsodium -o elfenc_pack && \
    gcc -O2 -Wall -Wextra \
        kcap_pack.c -lsodium -o kcap_pack && \
    gcc -O2 -Wall -Wextra \
        genkey.c -lsodium -o genkey && \
    gcc -O2 hello.c -o hello

# Generate keypair, encrypt hello, create capsule
# In production, you'd do this on your trusted build machine — not inside Docker.
# This is here for the self-contained demo only.
ARG ELFDEC_CODE=demo-secret-change-me
RUN ./genkey && \
    ./elfenc_pack pub.bin hello hello.elfenc && \
    ./kcap_pack --label demo/hello --code "${ELFDEC_CODE}" \
        --in priv.bin --out capsule.bin && \
    # Verify the private key is NOT shipped
    rm -f priv.bin pub.bin hello

# ── Stage 2: Minimal runtime image ──
FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libsodium23 libkeyutils1 && \
    rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -r -s /usr/sbin/nologin appuser

COPY --from=builder /build/elfdec-run /usr/local/bin/elfdec-run
COPY --from=builder /build/hello.elfenc /app/hello.elfenc
COPY --from=builder /build/capsule.bin /app/capsule.bin

RUN chmod 0755 /usr/local/bin/elfdec-run && \
    chown -R appuser:appuser /app

USER appuser
WORKDIR /app

ENV ELFDEC_KEYPATH=/app

# ELFDEC_CODE must be provided at runtime
ENTRYPOINT ["/usr/local/bin/elfdec-run"]
CMD ["/app/hello.elfenc"]
