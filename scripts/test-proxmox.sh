#!/bin/bash
# E2E test with Proxmox provider (CAPMOX)
#
# Prerequisites:
# 1. Copy and customize the example CRD files:
#    cp crates/lattice-cli/tests/e2e/fixtures/proxmox-mgmt-example.yaml clusters/proxmox-mgmt.yaml
#    cp crates/lattice-cli/tests/e2e/fixtures/proxmox-workload-example.yaml clusters/proxmox-workload.yaml
#
# 2. Create the Proxmox credentials secret on the bootstrap cluster:
#    kubectl create secret generic proxmox-credentials \
#      --from-literal=url='https://proxmox.example.com:8006' \
#      --from-literal=token='user@pam!token-name' \
#      --from-literal=secret='your-token-secret' \
#      -n lattice-system
#
# 3. Update the CRD files with your infrastructure details:
#    - sourceNode: Your Proxmox node name
#    - templateId: VM template ID with cloud-init
#    - controlPlaneEndpoint: VIP for each cluster (must be different)
#    - ipv4Addresses: IPs for each VM (must not overlap)
#    - sshAuthorizedKeys: Your SSH public key

set -e

# Path to your customized CRD files
export LATTICE_MGMT_CLUSTER_CONFIG="${LATTICE_MGMT_CLUSTER_CONFIG:-clusters/proxmox-mgmt.yaml}"
export LATTICE_WORKLOAD_CLUSTER_CONFIG="${LATTICE_WORKLOAD_CLUSTER_CONFIG:-clusters/proxmox-workload.yaml}"

# Provider hints for test behavior
export LATTICE_MGMT_PROVIDER=proxmox
export LATTICE_WORKLOAD_PROVIDER=proxmox

# Verify CRD files exist
if [[ ! -f "$LATTICE_MGMT_CLUSTER_CONFIG" ]]; then
    echo "Error: Management cluster CRD not found: $LATTICE_MGMT_CLUSTER_CONFIG"
    echo "Copy and customize the example: crates/lattice-cli/tests/e2e/fixtures/proxmox-mgmt-example.yaml"
    exit 1
fi

if [[ ! -f "$LATTICE_WORKLOAD_CLUSTER_CONFIG" ]]; then
    echo "Error: Workload cluster CRD not found: $LATTICE_WORKLOAD_CLUSTER_CONFIG"
    echo "Copy and customize the example: crates/lattice-cli/tests/e2e/fixtures/proxmox-workload-example.yaml"
    exit 1
fi

echo "Using management cluster config: $LATTICE_MGMT_CLUSTER_CONFIG"
echo "Using workload cluster config: $LATTICE_WORKLOAD_CLUSTER_CONFIG"
echo

RUST_LOG=info cargo test -p lattice-cli --features provider-e2e --test e2e pivot_e2e -- --nocapture
