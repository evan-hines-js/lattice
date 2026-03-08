#!/usr/bin/env bash
# Sets up an nginx TCP proxy so the K8s API server (bound to 127.0.0.1)
# is reachable from other machines on the LAN at port 6443.
#
# Run AFTER a cluster exists (kubeconfig must be present).
#
# Usage: sudo ./setup-k8s-proxy.sh
#
# On the remote machine, set your kubeconfig to:
#   server: https://<this-machine-lan-ip>:6443
#   insecure-skip-tls-verify: true

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo $0"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")
KUBECONFIG_PATH="${REAL_HOME}/.kube/config"

K8S_PORT=$(grep -oP '"server":\s*"https://127\.0\.0\.1:\K[0-9]+' "$KUBECONFIG_PATH" 2>/dev/null || true)
if [ -z "$K8S_PORT" ]; then
    echo "ERROR: Could not find K8s API port in $KUBECONFIG_PATH"
    exit 1
fi

echo "==> Installing nginx..."
apt-get update -qq
apt-get install -y -qq nginx libnginx-mod-stream

echo "==> Configuring nginx stream proxy (0.0.0.0:6443 -> 127.0.0.1:${K8S_PORT})..."
cat > /etc/nginx/k8s-stream-proxy.conf <<EOF
stream {
    upstream k8s_api {
        server 127.0.0.1:${K8S_PORT};
    }

    server {
        listen 0.0.0.0:6443;
        proxy_pass k8s_api;
    }
}
EOF

if ! grep -q 'k8s-stream-proxy.conf' /etc/nginx/nginx.conf; then
    echo 'include /etc/nginx/k8s-stream-proxy.conf;' >> /etc/nginx/nginx.conf
fi

rm -f /etc/nginx/conf.d/k8s-proxy-stream.conf
rm -f /etc/nginx/sites-enabled/default

echo "==> Testing nginx config..."
nginx -t

echo "==> Restarting nginx..."
systemctl restart nginx
systemctl enable nginx

LAN_IP=$(hostname -I | awk '{print $1}')

echo "==> Updating kubeconfig for external access..."
# Replace local/docker IPs (127.0.0.1, 172.x.x.x) with LAN IP and proxy port
sudo -u "$REAL_USER" kubectl config set-cluster management \
    --server="https://${LAN_IP}:6443" \
    --insecure-skip-tls-verify=true

echo
echo "==> Done! K8s API proxied: https://${LAN_IP}:6443 -> 127.0.0.1:${K8S_PORT}"
echo "    Kubeconfig updated to use https://${LAN_IP}:6443"
