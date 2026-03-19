#!/usr/bin/env bash
# Build and push the route-adapter multi-arch image
set -euo pipefail

IMAGE="${IMAGE:-ghcr.io/evan-hines-js/lattice-route-adapter:latest}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building route-adapter: $IMAGE"

docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --push \
    -t "$IMAGE" \
    "$SCRIPT_DIR"
