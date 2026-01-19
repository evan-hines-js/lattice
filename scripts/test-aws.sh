#!/bin/bash
# E2E test with AWS provider (CAPA)
#
# Required environment variables for credentials:
#   AWS_ACCESS_KEY_ID - AWS access key
#   AWS_SECRET_ACCESS_KEY - AWS secret access key
#   AWS_REGION - AWS region (e.g., us-west-2)
#
# Optional:
#   AWS_SESSION_TOKEN - Session token for temporary credentials
#
# The installer will create the credentials secret automatically.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Verify required credentials
if [[ -z "$AWS_ACCESS_KEY_ID" ]]; then
    echo "Error: AWS_ACCESS_KEY_ID environment variable required"
    exit 1
fi
if [[ -z "$AWS_SECRET_ACCESS_KEY" ]]; then
    echo "Error: AWS_SECRET_ACCESS_KEY environment variable required"
    exit 1
fi
if [[ -z "$AWS_REGION" ]]; then
    echo "Error: AWS_REGION environment variable required"
    exit 1
fi

export LATTICE_MGMT_CLUSTER_CONFIG="$REPO_ROOT/crates/lattice-cli/tests/e2e/fixtures/clusters/aws-mgmt.yaml"
export LATTICE_WORKLOAD_CLUSTER_CONFIG="$REPO_ROOT/crates/lattice-cli/tests/e2e/fixtures/clusters/aws-workload.yaml"
export LATTICE_ENABLE_INDEPENDENCE_TEST=true
export LATTICE_ENABLE_MESH_TEST=true

echo "AWS Region: $AWS_REGION"
echo "Management cluster config: $LATTICE_MGMT_CLUSTER_CONFIG"
echo "Workload cluster config: $LATTICE_WORKLOAD_CLUSTER_CONFIG"
echo

RUST_LOG=info cargo test -p lattice-cli --features provider-e2e --test e2e pivot_e2e -- --nocapture
