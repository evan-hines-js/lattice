# =============================================================================
# Lattice Operator image
# =============================================================================
# Builder: Debian slim (rust + go for helm).
# Runtime: gcr.io/distroless/cc-debian12:nonroot.
#
# FIPS crypto comes from the operator binary itself (aws-lc-rs FIPS feature).
# The runtime base is no longer FIPS-validated; the binary-level guarantee
# remains.
# =============================================================================

ARG HELM_VERSION=4.1.1
ARG COSIGN_VERSION=3.0.6

# -----------------------------------------------------------------------------
# Stage 1: build helm from source, fetch cosign
# -----------------------------------------------------------------------------
FROM golang:1.25-bookworm AS go-builder

ARG HELM_VERSION
ARG COSIGN_VERSION
ENV CGO_ENABLED=0

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    git clone --depth 1 --branch v${HELM_VERSION} https://github.com/helm/helm.git /build/helm && \
    cd /build/helm && \
    make build && \
    cp bin/helm /usr/local/bin/helm

RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL -o /usr/local/bin/cosign \
        "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${ARCH}" && \
    chmod +x /usr/local/bin/cosign && \
    /usr/local/bin/cosign version

# -----------------------------------------------------------------------------
# Stage 2: build lattice-operator
# -----------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    protobuf-compiler \
    libprotobuf-dev \
    clang \
    libclang-dev \
    cmake \
    golang \
    perl \
    make \
    gcc \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# helm is needed by build.rs to pre-render charts
COPY --from=go-builder /usr/local/bin/helm /usr/local/bin/helm

WORKDIR /app
COPY Cargo.toml Cargo.lock versions.toml ./
COPY crates ./crates
COPY scripts/runtime ./scripts
# Pre-downloaded artifacts so build.rs skips network downloads.
# These are gitignored (large binaries), so they may not exist in CI.
# Create empty dirs as fallback — build.rs will download if missing.
RUN mkdir -p test-charts test-providers
COPY test-chart[s] ./test-charts/
COPY test-provider[s] ./test-providers/

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release -p lattice-operator --features fips && \
    cp /app/target/release/lattice-operator /usr/local/bin/lattice-operator

# -----------------------------------------------------------------------------
# Stage 3: runtime
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=rust-builder /usr/local/bin/lattice-operator /usr/local/bin/lattice-operator
COPY --from=go-builder /usr/local/bin/helm /usr/local/bin/helm
COPY --from=go-builder /usr/local/bin/cosign /usr/local/bin/cosign
COPY --from=rust-builder /app/test-providers /providers

ENV PROVIDERS_DIR=/providers

ENTRYPOINT ["/usr/local/bin/lattice-operator"]
