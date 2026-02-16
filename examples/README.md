# Lattice Examples

Production-ready examples for provisioning clusters and deploying services with bilateral mesh agreements.

## Cluster Provisioning

The `cluster/` directory contains a LatticeCluster manifest for local development using Docker:

```bash
lattice install -f examples/cluster/management-cluster.yaml
```

This will:
1. Create a temporary kind bootstrap cluster
2. Deploy CAPI and the Lattice operator
3. Create the CloudProvider and credentials automatically (based on `providerRef` and `provider.config`)
4. Provision the management cluster
5. Pivot CAPI resources to make it self-managing
6. Delete the bootstrap cluster

After install, the cluster is fully self-managing. The `parentConfig` section is included so it can optionally provision child clusters later.

## Webapp Deployment

The `webapp/` directory deploys a 5-service application with bilateral mesh agreements:

```
Browser -> [Ingress] -> frontend:80 -> api:3000 -> postgres:5432
                                              \-> redis:6379
                                     worker -> api:3000 (health)
                                            -> postgres:5432
                                            -> redis:6379
```

### Bilateral Agreement Matrix

| Service  | Outbound To          | Inbound From     |
|----------|----------------------|------------------|
| frontend | api                  | (ingress only)   |
| api      | postgres, redis      | frontend, worker |
| postgres | (none)               | api, worker      |
| redis    | (none)               | api, worker      |
| worker   | api, postgres, redis | (none)           |

Traffic is only allowed when **both sides agree**: the caller declares `direction: outbound` and the callee declares `direction: inbound`. All other traffic is denied by default (Cilium L4 + Istio L7).

### Secrets Setup

Create the backing secrets before deploying the webapp:

```bash
kubectl -n lattice-secrets create secret generic webapp-db-credentials \
  --from-literal=password=changeme

kubectl -n lattice-secrets create secret generic webapp-redis-credentials \
  --from-literal=password=changeme
```

### Deploy

```bash
kubectl apply -f examples/webapp/namespace.yaml
kubectl apply -f examples/webapp/postgres.yaml
kubectl apply -f examples/webapp/redis.yaml
kubectl apply -f examples/webapp/api.yaml
kubectl apply -f examples/webapp/worker.yaml
kubectl apply -f examples/webapp/frontend.yaml
```

### Access

Add `webapp.local` to `/etc/hosts` pointing to your ingress IP, then visit `http://webapp.local` to see the frontend page with live API status.

## Media Stack

The `media/` directory deploys a homelab media server stack with shared storage and bilateral mesh agreements:

```
sonarr:8989 -> nzbget:6789 (download requests)
sonarr:8989 -> jellyfin:8096 (library refresh)
jellyfin:8096 -> repo.jellyfin.org (external, plugin updates)
nzbget:6789 -> egress-vpn (wireguard egress gateway)
```

### Bilateral Agreement Matrix

| Service      | Outbound To        | Inbound From |
|--------------|--------------------|--------------|
| jellyfin     | jellyfin-repo (ext)| sonarr       |
| sonarr       | nzbget, jellyfin   | (none)       |
| nzbget       | egress-vpn         | sonarr       |
| egress-vpn   | (none)             | nzbget       |

### Shared Volume

Jellyfin owns a 100Gi `media-storage` volume and grants access to sonarr and nzbget via `allowedConsumers`. Sonarr and nzbget reference it by ID without specifying a size.

### VPN Egress Gateway

Nzbget routes its download traffic through a wireguard egress gateway via bilateral mesh agreement. The gateway tunnels all traffic it receives through a wireguard VPN. Edit `egress-vpn.yaml` with your wireguard credentials before deploying.

### Deploy

```bash
kubectl apply -f examples/media/namespace.yaml
kubectl apply -f examples/media/jellyfin-repo.yaml
kubectl apply -f examples/media/jellyfin.yaml
kubectl apply -f examples/media/sonarr.yaml
kubectl apply -f examples/media/egress-vpn.yaml
kubectl apply -f examples/media/nzbget.yaml
```

### Access

Add `*.home.arpa` entries to `/etc/hosts` pointing to your ingress IP:

- `https://jellyfin.home.arpa` - Jellyfin media server
- `https://sonarr.home.arpa` - Sonarr TV management
- `https://nzbget.home.arpa` - NZBGet download client
