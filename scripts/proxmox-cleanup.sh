#!/usr/bin/env bash
# Delete all Proxmox VMs except protected IDs (parallel).
# Protected: 100 (base), 9000/9001 (CAPI VM templates).
# Usage: ./scripts/proxmox-cleanup.sh [--dry-run]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SCRIPT_DIR/.proxmox.credentials"

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

CURL="curl -sSk"
AUTH="PVEAPIToken=${PROXMOX_TOKEN}=${PROXMOX_SECRET}"
API="${PROXMOX_URL}/api2/json"

NODES=$($CURL -H "Authorization: $AUTH" "$API/nodes" | jq -r '.data[].node' | sort)
echo "Nodes: $NODES"

delete_vm() {
  local NODE=$1
  local VMID=$2
  local STATUS
  STATUS=$($CURL -H "Authorization: $AUTH" "$API/nodes/$NODE/qemu/$VMID/status/current" \
    | jq -r '.data.status')

  if [[ "$STATUS" == "running" ]]; then
    echo "[$NODE/$VMID] Stopping..."
    $CURL -X POST -H "Authorization: $AUTH" "$API/nodes/$NODE/qemu/$VMID/status/stop" > /dev/null
    for _ in $(seq 1 30); do
      S=$($CURL -H "Authorization: $AUTH" "$API/nodes/$NODE/qemu/$VMID/status/current" \
        | jq -r '.data.status')
      [[ "$S" == "stopped" ]] && break
      sleep 2
    done
  fi

  $CURL -X DELETE -H "Authorization: $AUTH" \
    "$API/nodes/$NODE/qemu/$VMID?destroy-unreferenced-disks=1&purge=1" > /dev/null
  echo "[$NODE/$VMID] Deleted"
}

for NODE in $NODES; do
  echo "--- Node: $NODE ---"
  VMIDS=$($CURL -H "Authorization: $AUTH" "$API/nodes/$NODE/qemu" \
    | jq -r '.data[].vmid' | sort -n)

  for VMID in $VMIDS; do
    if [[ "$VMID" -eq 100 || "$VMID" -eq 101 || "$VMID" -eq 9000 || "$VMID" -eq 9001 ]]; then
      echo "SKIP $NODE/$VMID (protected)"
      continue
    fi
    if $DRY_RUN; then
      echo "DRY-RUN: would delete VM $NODE/$VMID"
    else
      delete_vm "$NODE" "$VMID" &
    fi
  done
done

wait
echo "Done."
