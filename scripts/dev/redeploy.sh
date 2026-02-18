#!/usr/bin/env bash
# Rebuild the lattice image and push to registry.
#
# Usage:
#   ./scripts/dev/redeploy.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="ghcr.io/evan-hines-js/lattice:latest"

echo "=== Building and pushing $IMAGE ==="
"$SCRIPT_DIR/docker-build.sh" -t "$IMAGE" --push
echo "=== Done ==="
