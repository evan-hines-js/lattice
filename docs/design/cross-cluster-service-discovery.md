# Cross-Cluster Service Discovery

## Overview

Services in one cluster can depend on services in other clusters. This design enables discovery and routing across the cluster hierarchy using the existing agent-cell gRPC streams.

## Scale Target

- 500-1000 total services across all clusters
- 50-100 clusters in hierarchy
- <100ms cold lookup, <10ms cached
- Memory: ~5MB for full catalog

## Architecture

```
                    ┌─────────────────┐
                    │  Root Cluster   │
                    │  (Catalog: B,C) │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
     ┌────────▼────────┐          ┌────────▼────────┐
     │   Cluster B     │          │   Cluster C     │
     │ (Catalog: B1,B2)│          │ (Catalog: C1)   │
     └────────┬────────┘          └────────┬────────┘
              │                             │
      ┌───────┴───────┐                     │
      │               │                     │
┌─────▼─────┐  ┌─────▼─────┐         ┌─────▼─────┐
│ Cluster B1│  │ Cluster B2│         │ Cluster C1│
│ (web)     │  │ (api)     │         │ (db)      │
└───────────┘  └───────────┘         └───────────┘
```

Each cluster maintains a **ServiceCatalog** containing services announced by its direct children. Queries that can't be resolved locally are forwarded to the parent.

## Data Flow

### 1. Service Announcement (child → parent)

When a LatticeService is created/updated/deleted, the agent announces it to the parent cell:

```
Child Agent ──ServiceAnnouncement──► Parent Cell
                                         │
                                         ▼
                                   ServiceCatalog
```

Announcements propagate up automatically - when a parent's catalog changes, it announces the aggregate to its parent.

### 2. Service Query (recursive up the tree)

When a service has an Unknown dependency, the agent queries the parent:

```
Child: "Where is service 'api' in namespace 'default'?"
    │
    ▼
Parent: Check local catalog
    │
    ├─► Found locally → Return endpoints + validate bilateral
    │
    └─► Not found → Forward query to own parent (recursive)
                         │
                         ▼
                    Eventually reaches a node that has it
                         │
                         ▼
                    Response flows back down
```

### 3. Bilateral Agreement Validation

The node that owns the service info validates the bilateral agreement:

```
Query: { service: "api", requester: "web", requester_cluster: "B1" }

Catalog lookup: api.allowed_requesters = ["web", "frontend"]

Check: "web" in allowed_requesters?
  → Yes: Return { found: true, access_allowed: true, endpoints: [...] }
  → No:  Return { found: true, access_allowed: false }
```

## Proto Messages

```protobuf
// Add to agent.proto

message ServiceAnnouncement {
  string cluster = 1;           // originating cluster
  string namespace = 2;
  string name = 3;
  repeated string endpoints = 4; // ip:port list
  repeated string allowed_requesters = 5; // services allowed to call this
  bool deleted = 6;             // true = remove from catalog
}

message ServiceQuery {
  string namespace = 1;
  string name = 2;
  string requester_cluster = 3;  // cluster making the request
  string requester_service = 4;  // service making the request (for bilateral check)
}

message ServiceQueryResponse {
  bool found = 1;
  bool access_allowed = 2;       // bilateral agreement valid?
  string owner_cluster = 3;      // which cluster owns this service
  repeated string endpoints = 4;
  string error = 5;              // if found=false, why
}

// Extend existing messages:

message AgentMessage {
  oneof payload {
    // ... existing ...
    ServiceAnnouncement service_announcement = 10;
    ServiceQuery service_query = 11;
  }
}

message CellCommand {
  oneof payload {
    // ... existing ...
    ServiceQueryResponse service_query_response = 10;
    ServiceAnnouncement service_announcement = 11; // forwarded from children
  }
}
```

## Implementation

### ServiceCatalog (lattice-cluster/src/catalog.rs)

```rust
use dashmap::DashMap;

#[derive(Clone)]
pub struct ServiceInfo {
    pub cluster: String,
    pub namespace: String,
    pub name: String,
    pub endpoints: Vec<String>,
    pub allowed_requesters: Vec<String>,
}

pub struct ServiceCatalog {
    // Key: (namespace, name) - we track which cluster owns it
    services: DashMap<(String, String), ServiceInfo>,
}

impl ServiceCatalog {
    pub fn new() -> Self {
        Self { services: DashMap::new() }
    }

    pub fn upsert(&self, announcement: ServiceAnnouncement) {
        let key = (announcement.namespace.clone(), announcement.name.clone());
        if announcement.deleted {
            self.services.remove(&key);
        } else {
            self.services.insert(key, ServiceInfo::from(announcement));
        }
    }

    pub fn query(&self, query: &ServiceQuery) -> Option<ServiceQueryResponse> {
        let key = (query.namespace.clone(), query.name.clone());
        self.services.get(&key).map(|info| {
            let access_allowed = info.allowed_requesters.contains(&query.requester_service);
            ServiceQueryResponse {
                found: true,
                access_allowed,
                owner_cluster: info.cluster.clone(),
                endpoints: info.endpoints.clone(),
                error: String::new(),
            }
        })
    }

    pub fn all_services(&self) -> Vec<ServiceInfo> {
        self.services.iter().map(|r| r.value().clone()).collect()
    }
}
```

### Cell Server Changes (lattice-cluster/src/agent/server.rs)

```rust
impl CellServer {
    async fn handle_agent_message(&self, cluster_name: &str, msg: AgentMessage) {
        match msg.payload {
            // ... existing handlers ...

            Some(Payload::ServiceAnnouncement(ann)) => {
                // Store in local catalog
                self.catalog.upsert(ann.clone());

                // If we have a parent, forward the announcement up
                if let Some(parent) = &self.parent_client {
                    parent.announce(ann).await;
                }
            }

            Some(Payload::ServiceQuery(query)) => {
                let response = self.resolve_service_query(query).await;
                self.send_to_agent(cluster_name, CellCommand::ServiceQueryResponse(response));
            }
        }
    }

    async fn resolve_service_query(&self, query: ServiceQuery) -> ServiceQueryResponse {
        // Check local catalog first
        if let Some(response) = self.catalog.query(&query) {
            return response;
        }

        // Not found locally - forward to parent if we have one
        if let Some(parent) = &self.parent_client {
            return parent.query(query).await;
        }

        // No parent, service not found
        ServiceQueryResponse {
            found: false,
            access_allowed: false,
            owner_cluster: String::new(),
            endpoints: vec![],
            error: "service not found in hierarchy".into(),
        }
    }
}
```

### Agent Client Changes (lattice-cluster/src/agent/client.rs)

```rust
impl AgentClient {
    // Cache for resolved remote services
    cache: DashMap<(String, String), ServiceQueryResponse>,

    pub async fn announce(&self, service: &LatticeService) {
        let announcement = ServiceAnnouncement {
            cluster: self.cluster_name.clone(),
            namespace: service.metadata.namespace.clone().unwrap_or_default(),
            name: service.metadata.name.clone().unwrap_or_default(),
            endpoints: service.status.endpoints.clone(),
            allowed_requesters: extract_allowed_requesters(service),
            deleted: false,
        };
        self.send(AgentMessage::ServiceAnnouncement(announcement)).await;
    }

    pub async fn query(&self, namespace: &str, name: &str, requester: &str) -> ServiceQueryResponse {
        let key = (namespace.to_string(), name.to_string());

        // Check cache first
        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }

        // Query parent
        let query = ServiceQuery {
            namespace: namespace.to_string(),
            name: name.to_string(),
            requester_cluster: self.cluster_name.clone(),
            requester_service: requester.to_string(),
        };

        let response = self.query_parent(query).await;

        // Cache successful lookups
        if response.found {
            self.cache.insert(key, response.clone());
        }

        response
    }
}
```

### Service Controller Integration (lattice-service/src/controller.rs)

```rust
async fn reconcile(service: Arc<LatticeService>, ctx: Arc<Context>) -> Result<Action> {
    // ... existing logic ...

    // Check for unknown dependencies
    let unknown_deps = get_unknown_dependencies(&service, &graph);

    for dep in unknown_deps {
        let response = ctx.agent_client.query(
            &dep.namespace,
            &dep.name,
            &service.metadata.name.unwrap_or_default(),
        ).await;

        if !response.found {
            // Dependency not found anywhere - requeue and wait
            return Ok(Action::requeue(Duration::from_secs(30)));
        }

        if !response.access_allowed {
            // Bilateral agreement not satisfied
            update_status(&service, "Denied", &format!(
                "Access to {} denied - not in allowed_requesters", dep.name
            )).await;
            return Ok(Action::requeue(Duration::from_secs(60)));
        }

        // Generate Istio ServiceEntry for the remote service
        let service_entry = generate_service_entry(&dep, &response);
        apply_resource(&ctx.client, &service_entry).await?;
    }

    // ... continue with policy generation ...
}
```

### ServiceEntry Generation

```rust
fn generate_service_entry(dep: &Dependency, remote: &ServiceQueryResponse) -> ServiceEntry {
    ServiceEntry {
        metadata: ObjectMeta {
            name: Some(format!("{}-{}-remote", dep.namespace, dep.name)),
            namespace: Some("istio-system".to_string()),
            ..Default::default()
        },
        spec: ServiceEntrySpec {
            hosts: vec![format!("{}.{}.global", dep.name, dep.namespace)],
            location: Location::MeshInternal,  // mTLS via mesh
            resolution: Resolution::Static,
            ports: vec![Port {
                number: 80,
                name: "http".to_string(),
                protocol: "HTTP".to_string(),
            }],
            endpoints: remote.endpoints.iter().map(|ep| {
                Endpoint {
                    address: ep.clone(),
                    ..Default::default()
                }
            }).collect(),
        },
    }
}
```

## Caching Strategy

**Simple approach for v1:**
- Cache never expires (services are stable)
- Cache invalidated on ServiceAnnouncement with `deleted=true`
- Full cache rebuild on agent reconnect (re-query all Unknown deps)

**Future optimization:**
- TTL-based refresh (query again after N minutes)
- Parent pushes updates when catalog changes

## Failure Modes

| Failure | Behavior |
|---------|----------|
| Parent disconnected | Use cached data, queries return cached or "unavailable" |
| Service deleted | Parent sends announcement with deleted=true, cache cleared |
| Circular dependency | Detected at query time, return error |
| Root has no answer | Return "not found in hierarchy" |

## Testing

E2E test flow:
1. Create Cluster A with service "web" that depends on "api"
2. Create Cluster B with service "api" that allows "web"
3. Verify "web" can discover "api" via parent
4. Verify ServiceEntry created in Cluster A
5. Delete "api", verify cache cleared and "web" status updates

## File Changes

| File | Change |
|------|--------|
| `crates/lattice-proto/proto/agent.proto` | Add messages (~30 lines) |
| `crates/lattice-cluster/src/catalog.rs` | New file (~100 lines) |
| `crates/lattice-cluster/src/agent/server.rs` | Handle announcements/queries (~50 lines) |
| `crates/lattice-cluster/src/agent/client.rs` | Announce/query methods (~50 lines) |
| `crates/lattice-service/src/controller.rs` | Resolve unknown deps (~30 lines) |
| `crates/lattice-service/src/resources/service_entry.rs` | Generate ServiceEntry (~50 lines) |

**Total: ~300 lines of new code**
