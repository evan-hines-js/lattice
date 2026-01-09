# Build stage
# Note: Requires Rust 1.88+ due to home crate dependency
FROM rust:latest AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libclang-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy everything needed for build
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src

# Build the binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies and tools
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install kubectl
ARG TARGETARCH
RUN ARCH=$(echo ${TARGETARCH:-amd64} | sed 's/arm64/arm64/;s/amd64/amd64/') && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${ARCH}/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

# Install clusterctl for pivot operations
RUN ARCH=$(echo ${TARGETARCH:-amd64} | sed 's/arm64/arm64/;s/amd64/amd64/') && \
    curl -L "https://github.com/kubernetes-sigs/cluster-api/releases/download/v1.9.4/clusterctl-linux-${ARCH}" -o /usr/local/bin/clusterctl && \
    chmod +x /usr/local/bin/clusterctl

# Copy binary from builder
COPY --from=builder /app/target/release/lattice /usr/local/bin/lattice

# Create non-root user
RUN useradd -r -u 1000 lattice
USER lattice

ENTRYPOINT ["/usr/local/bin/lattice"]
