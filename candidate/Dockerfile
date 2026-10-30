# Candidate image: the pinned reference image with /bin/authentik replaced by
# the binary built from rust/. Everything else (Python, web UI, blueprints,
# entrypoint) is byte-identical to the reference, so any behavioral
# difference is attributable to the Rust changes.
ARG REFERENCE_IMAGE=ghcr.io/goauthentik/server:2026.8.5

FROM ${REFERENCE_IMAGE} AS reference

# Mirrors the upstream `rust-builder` stage: same Python base (pyo3 links the
# image's libpython), same toolchain and aws-lc FIPS build dependencies.
FROM reference AS rust-builder
USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential cmake clang golang curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENV AWS_LC_FIPS_SYS_CC=clang
# The reference image points TMPDIR at /dev/shm, which is mounted noexec.
ENV TMPDIR=/root/tmp
RUN mkdir -p /root/tmp
ENV PATH="/root/.cargo/bin:$PATH"
COPY rust-toolchain.toml /build/rust-toolchain.toml
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain "$(sed -n 's/^channel = "\(.*\)"/\1/p' /build/rust-toolchain.toml)"
WORKDIR /build
COPY . /build
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --package authentik --no-default-features --features core --locked --release && \
    cp ./target/release/authentik /bin/authentik-candidate

FROM reference
COPY --from=rust-builder /bin/authentik-candidate /bin/authentik
