//! HAProxy route adapter for LatticeClusterRoutes
//!
//! Watches its own `LatticeService` for the hostname list to serve and
//! `LatticeClusterRoutes` for the union of advertised backends across the
//! cluster tree. Renders haproxy.cfg, sends SIGUSR2 to the HAProxy master
//! process for zero-downtime reload.
//!
//! Hostname → backend resolution: the hostname's first label is the backend
//! service name (`jellyfin.home.arpa` → service `jellyfin`). Matching
//! `ClusterRoute` is found by service name across all advertised clusters.
//! When the route advertises a directly-routable address (a LoadBalancer VIP
//! resolved by the route reconciler), haproxy connects to it directly over
//! plain TCP; otherwise haproxy connects to the in-cluster service FQDN and
//! ztunnel handles cross-cluster HBONE tunneling transparently.
//!
//! This is a standalone sidecar — not part of Lattice core. Anyone can
//! write an adapter for their preferred data plane (nginx, envoy, etc.)
//! by watching the same CRDs.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::PathBuf;

use futures::TryStreamExt;
use kube::api::{Api, DynamicObject};
use kube::discovery::ApiResource;
use kube::runtime::watcher::{self, Event};
use kube::Client;
use serde::Deserialize;
use tracing::{error, info, warn};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterRoutesSpec {
    #[serde(default)]
    routes: Vec<ClusterRoute>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterRoute {
    service_name: String,
    service_namespace: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    service_ports: BTreeMap<String, u16>,
}

impl ClusterRoute {
    /// HAProxy backend target for this route.
    ///
    /// Prefers the directly-routable LB VIP (`address:port`) when set, so the
    /// proxy → backend hop bypasses the mesh. Falls back to the in-cluster
    /// FQDN — ztunnel handles cross-cluster HBONE tunneling from there.
    fn backend_target(&self) -> (String, u16) {
        if !self.address.is_empty() && self.port > 0 {
            return (self.address.clone(), self.port);
        }
        let host = format!(
            "{}.{}.svc.cluster.local",
            self.service_name, self.service_namespace
        );
        let port = self
            .service_ports
            .values()
            .next()
            .copied()
            .unwrap_or(self.port);
        (host, port)
    }
}

/// A `(hostname, backend service name)` pair derived from this proxy's own
/// `LatticeService.spec.ingress`.
struct HostBinding {
    hostname: String,
    service_name: String,
}

impl HostBinding {
    /// Sanitized ACL/backend identifier: alphanumeric + underscore only.
    fn ident(&self) -> String {
        self.hostname
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LatticeServiceSpec {
    #[serde(default)]
    ingress: Option<IngressSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IngressSpec {
    #[serde(default)]
    routes: BTreeMap<String, RouteSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteSpec {
    #[serde(default)]
    hosts: Vec<String>,
}

const HOSTNAME_NS: &str = "edge"; // adapter is namespace-scoped to its own LatticeService

fn render_haproxy_config(bindings: &[HostBinding], routes: &[ClusterRoute]) -> String {
    let mut cfg = String::with_capacity(4096);

    cfg.push_str(
        r#"global
    log stdout format raw local0
    master-worker

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  forwardfor
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout http-keep-alive 5s
    retries 3
    retry-on 502 conn-failure empty-response response-timeout
    option http-server-close
    http-reuse never

frontend stats
    bind *:8405
    http-request return status 200 content-type text/plain string "ok" if { path /healthz }
    stats enable
    stats uri /stats

"#,
    );

    let by_service: BTreeMap<&str, &ClusterRoute> =
        routes.iter().map(|r| (r.service_name.as_str(), r)).collect();

    let resolved: Vec<(&HostBinding, &ClusterRoute)> = bindings
        .iter()
        .filter_map(|b| match by_service.get(b.service_name.as_str()) {
            Some(r) => Some((b, *r)),
            None => {
                warn!(
                    hostname = %b.hostname,
                    service = %b.service_name,
                    available_services = ?by_service.keys().collect::<Vec<_>>(),
                    "no advertised ClusterRoute for hostname's service — skipping"
                );
                None
            }
        })
        .collect();

    for (b, r) in &resolved {
        let (host, port) = r.backend_target();
        info!(
            hostname = %b.hostname,
            service = %b.service_name,
            ident = %b.ident(),
            backend = %format!("{host}:{port}"),
            "resolved hostname → backend"
        );
    }

    if resolved.is_empty() {
        cfg.push_str(
            r#"frontend http_in
    bind *:8080
    default_backend empty

backend empty
    http-request return status 503 content-type text/plain string "no backends configured"
"#,
        );
        return cfg;
    }

    cfg.push_str("frontend http_in\n    bind *:8080\n");
    for (b, _) in &resolved {
        let _ = writeln!(
            cfg,
            "    acl host_{} hdr(host) -i {}",
            b.ident(),
            b.hostname
        );
    }
    cfg.push('\n');
    for (b, _) in &resolved {
        let _ = writeln!(cfg, "    use_backend be_{} if host_{}", b.ident(), b.ident());
    }
    cfg.push_str("    default_backend fallback\n\n");

    for (b, route) in &resolved {
        let (host, port) = route.backend_target();
        let _ = writeln!(cfg, "backend be_{}\n    server gw {}:{}\n", b.ident(), host, port);
    }

    cfg.push_str(
        r#"backend fallback
    http-request return status 404 content-type text/plain string "unknown host"
"#,
    );

    let _ = HOSTNAME_NS; // reserved for a future explicit-namespace lookup mode
    cfg
}

fn find_pid(process_name: &str) -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_str().unwrap_or("");
        if pid_str.is_empty() || !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(cmdline) = std::fs::read_to_string(entry.path().join("cmdline")) {
            if cmdline
                .split('\0')
                .next()
                .map_or(false, |a| a.contains(process_name))
            {
                return pid_str.parse().ok();
            }
        }
    }
    None
}

fn reload_haproxy(process_name: &str) {
    match find_pid(process_name) {
        Some(pid) => {
            let result = unsafe { libc::kill(pid, libc::SIGUSR2) };
            if result == 0 {
                info!(pid, "sent SIGUSR2 to haproxy");
            } else {
                let err = std::io::Error::last_os_error();
                error!(pid, %err, "failed to send SIGUSR2");
            }
        }
        None => warn!("haproxy process not found, skipping reload"),
    }
}

async fn list_all_routes(client: &Client, ar: &ApiResource) -> Vec<ClusterRoute> {
    let api: Api<DynamicObject> = Api::all_with(client.clone(), ar);
    let list = match api.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            error!(%e, "failed to list LatticeClusterRoutes");
            return Vec::new();
        }
    };

    let mut routes = Vec::new();
    for item in &list.items {
        if let Some(spec) = item.data.get("spec") {
            if let Ok(parsed) = serde_json::from_value::<ClusterRoutesSpec>(spec.clone()) {
                routes.extend(parsed.routes);
            }
        }
    }
    routes
}

/// Read this adapter's own `LatticeService` and derive the `(hostname,
/// service_name)` bindings from its ingress route hosts.
async fn read_own_bindings(
    client: &Client,
    ar: &ApiResource,
    workload_name: &str,
    workload_namespace: &str,
) -> Vec<HostBinding> {
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), workload_namespace, ar);
    let obj = match api.get(workload_name).await {
        Ok(obj) => obj,
        Err(e) => {
            error!(%e, name = %workload_name, ns = %workload_namespace, "failed to read own LatticeService");
            return Vec::new();
        }
    };

    let spec: LatticeServiceSpec = match obj.data.get("spec") {
        Some(s) => match serde_json::from_value(s.clone()) {
            Ok(parsed) => parsed,
            Err(e) => {
                error!(%e, "failed to parse own LatticeService.spec");
                return Vec::new();
            }
        },
        None => return Vec::new(),
    };

    let ingress = match spec.ingress {
        Some(i) => i,
        None => return Vec::new(),
    };

    let mut bindings = Vec::new();
    for route in ingress.routes.values() {
        for hostname in &route.hosts {
            let service_name = match hostname.split_once('.') {
                Some((first, _)) if !first.is_empty() => first.to_string(),
                _ => {
                    warn!(hostname = %hostname, "hostname has no first-label service name; skipping");
                    continue;
                }
            };
            bindings.push(HostBinding {
                hostname: hostname.clone(),
                service_name,
            });
        }
    }
    bindings
}

async fn run_watcher(
    client: &Client,
    routes_ar: &ApiResource,
    service_ar: &ApiResource,
    workload_name: &str,
    workload_namespace: &str,
    config_path: &PathBuf,
    process_name: &str,
) {
    let api: Api<DynamicObject> = Api::all_with(client.clone(), routes_ar);
    let mut stream = std::pin::pin!(watcher::watcher(api, watcher::Config::default()));
    let mut last_config = String::new();

    loop {
        match stream.try_next().await {
            Ok(Some(event)) => {
                if !matches!(event, Event::Apply(_) | Event::Delete(_) | Event::InitDone) {
                    continue;
                }

                let all_routes = list_all_routes(client, routes_ar).await;
                let bindings =
                    read_own_bindings(client, service_ar, workload_name, workload_namespace).await;
                let config = render_haproxy_config(&bindings, &all_routes);

                if config == last_config {
                    continue;
                }

                match std::fs::write(config_path, &config) {
                    Ok(()) => {
                        info!(
                            routes = all_routes.len(),
                            bindings = bindings.len(),
                            config_bytes = config.len(),
                            "wrote haproxy.cfg"
                        );
                        // Inline the rendered config so it's visible via
                        // kubectl logs without needing `exec` (which Tetragon
                        // policy blocks on this workload).
                        for line in config.lines() {
                            info!(target: "haproxy_cfg", "{}", line);
                        }
                        reload_haproxy(process_name);
                        last_config = config;
                    }
                    Err(e) => error!(%e, "failed to write haproxy.cfg"),
                }
            }
            Ok(None) => {
                warn!("watcher stream ended");
                break;
            }
            Err(e) => {
                error!(%e, "watcher error");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, namespace: &str, address: &str, port: u16, svc_ports: &[(&str, u16)]) -> ClusterRoute {
        let mut sp = BTreeMap::new();
        for (k, v) in svc_ports {
            sp.insert((*k).to_string(), *v);
        }
        ClusterRoute {
            service_name: name.into(),
            service_namespace: namespace.into(),
            address: address.into(),
            port,
            service_ports: sp,
        }
    }

    fn binding(hostname: &str) -> HostBinding {
        let service_name = hostname.split_once('.').map(|(s, _)| s.to_string()).unwrap_or_default();
        HostBinding {
            hostname: hostname.into(),
            service_name,
        }
    }

    #[test]
    fn lb_backed_service_renders_direct_address_backend() {
        let routes = vec![route("jellyfin", "media", "10.0.0.42", 8096, &[("http", 8096)])];
        let bindings = vec![binding("jellyfin.home.arpa")];
        let cfg = render_haproxy_config(&bindings, &routes);
        assert!(cfg.contains("acl host_jellyfin_home_arpa hdr(host) -i jellyfin.home.arpa"));
        assert!(cfg.contains("server gw 10.0.0.42:8096"));
        assert!(!cfg.contains("svc.cluster.local"));
    }

    #[test]
    fn mesh_internal_service_renders_fqdn_backend() {
        let routes = vec![route("sonarr", "media", "", 0, &[("http", 8989)])];
        let bindings = vec![binding("sonarr.home.arpa")];
        let cfg = render_haproxy_config(&bindings, &routes);
        assert!(cfg.contains("acl host_sonarr_home_arpa hdr(host) -i sonarr.home.arpa"));
        assert!(cfg.contains("server gw sonarr.media.svc.cluster.local:8989"));
    }

    #[test]
    fn unbound_hostname_is_skipped() {
        let routes = vec![route("jellyfin", "media", "10.0.0.42", 8096, &[("http", 8096)])];
        let bindings = vec![binding("jellyfin.home.arpa"), binding("ghost.home.arpa")];
        let cfg = render_haproxy_config(&bindings, &routes);
        assert!(cfg.contains("acl host_jellyfin_home_arpa"));
        assert!(!cfg.contains("ghost.home.arpa"));
    }

    #[test]
    fn no_resolved_hostnames_emits_503_default() {
        let routes: Vec<ClusterRoute> = vec![];
        let bindings = vec![binding("anything.home.arpa")];
        let cfg = render_haproxy_config(&bindings, &routes);
        assert!(cfg.contains("backend empty"));
        assert!(cfg.contains("503"));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    let config_path = PathBuf::from(
        std::env::var("CONFIG_PATH").unwrap_or_else(|_| "/config/haproxy.cfg".to_string()),
    );
    let process_name =
        std::env::var("HAPROXY_PROCESS_NAME").unwrap_or_else(|_| "haproxy".to_string());
    let workload_name = std::env::var("WORKLOAD_NAME")
        .map_err(|_| "WORKLOAD_NAME env var is required (the LatticeService this adapter belongs to)")?;
    let workload_namespace = std::env::var("WORKLOAD_NAMESPACE")
        .map_err(|_| "WORKLOAD_NAMESPACE env var is required")?;

    info!(
        ?config_path,
        %process_name,
        workload = %workload_name,
        ns = %workload_namespace,
        "route adapter starting"
    );

    let client = Client::try_default().await?;

    let routes_ar = ApiResource {
        group: "lattice.dev".into(),
        version: "v1alpha1".into(),
        api_version: "lattice.dev/v1alpha1".into(),
        kind: "LatticeClusterRoutes".into(),
        plural: "latticeclusterroutes".into(),
    };
    let service_ar = ApiResource {
        group: "lattice.dev".into(),
        version: "v1alpha1".into(),
        api_version: "lattice.dev/v1alpha1".into(),
        kind: "LatticeService".into(),
        plural: "latticeservices".into(),
    };

    // Bootstrap empty config so HAProxy can start before any routes are seen.
    std::fs::write(&config_path, render_haproxy_config(&[], &[]))?;

    loop {
        run_watcher(
            &client,
            &routes_ar,
            &service_ar,
            &workload_name,
            &workload_namespace,
            &config_path,
            &process_name,
        )
        .await;
        info!("reconnecting watcher in 5s...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
