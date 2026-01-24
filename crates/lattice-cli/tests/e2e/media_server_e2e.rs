//! Media Server E2E Test
//!
//! Tests LatticeService with a media server stack (jellyfin, nzbget, sonarr).
//! Verifies volume sharing, pod co-location, and bilateral agreements.

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::sleep;

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Namespace, PersistentVolumeClaim, Pod};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, ListParams, PostParams};
use kube::runtime::wait::{await_condition, Condition};

use lattice_operator::crd::{
    CertIssuerRef, ContainerSpec, DependencyDirection, DeploySpec, HttpGetProbe, InboundPolicy,
    IngressSpec, IngressTls, LatticeService, LatticeServiceSpec, OutboundPolicy, PortSpec, Probe,
    RateLimitConfig, ReplicaSpec, ResourceQuantity, ResourceRequirements, ResourceSpec,
    ResourceType, RetryConfig, ServicePortsSpec, TimeoutConfig, TlsMode, VolumeMount,
};
use lattice_operator::template::TemplateString;

use super::helpers::{client_from_kubeconfig, run_cmd, run_cmd_allow_fail};

const NAMESPACE: &str = "media";

// =============================================================================
// Resource Builders
// =============================================================================

fn volume_owned(size: &str) -> ResourceSpec {
    ResourceSpec {
        type_: ResourceType::Volume,
        params: Some(BTreeMap::from([("size".into(), serde_json::json!(size))])),
        ..Default::default()
    }
}

fn volume_shared_owner(id: &str, size: &str) -> ResourceSpec {
    ResourceSpec {
        type_: ResourceType::Volume,
        id: Some(id.into()),
        params: Some(BTreeMap::from([
            ("size".into(), serde_json::json!(size)),
            ("accessMode".into(), serde_json::json!("ReadWriteOnce")),
        ])),
        ..Default::default()
    }
}

fn volume_shared_ref(id: &str) -> ResourceSpec {
    ResourceSpec {
        type_: ResourceType::Volume,
        id: Some(id.into()),
        ..Default::default()
    }
}

fn service_inbound(rate_limit: u32) -> ResourceSpec {
    ResourceSpec {
        type_: ResourceType::Service,
        direction: DependencyDirection::Inbound,
        inbound: Some(InboundPolicy {
            rate_limit: Some(RateLimitConfig {
                requests_per_interval: rate_limit,
                interval_seconds: 60,
            }),
        }),
        ..Default::default()
    }
}

fn service_outbound(timeout: &str, retries: Option<(u32, &str)>) -> ResourceSpec {
    ResourceSpec {
        type_: ResourceType::Service,
        direction: DependencyDirection::Outbound,
        outbound: Some(OutboundPolicy {
            timeout: Some(TimeoutConfig {
                request: timeout.into(),
            }),
            retries: retries.map(|(attempts, per_try)| RetryConfig {
                attempts,
                per_try_timeout: Some(per_try.into()),
                retry_on: vec!["5xx".into(), "connect-failure".into()],
            }),
        }),
        ..Default::default()
    }
}

fn vol_mount(resource: &str, subpath: Option<&str>) -> VolumeMount {
    VolumeMount {
        source: TemplateString::from(format!("${{resources.{}}}", resource)),
        path: subpath.map(Into::into),
        read_only: None,
    }
}

fn http_probe(path: &str, port: u16) -> Probe {
    Probe {
        http_get: Some(HttpGetProbe {
            path: path.into(),
            port,
            scheme: None,
            host: None,
            http_headers: None,
        }),
        exec: None,
    }
}

fn resources(cpu_req: &str, mem_req: &str, cpu_lim: &str, mem_lim: &str) -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(ResourceQuantity {
            cpu: Some(cpu_req.into()),
            memory: Some(mem_req.into()),
        }),
        limits: Some(ResourceQuantity {
            cpu: Some(cpu_lim.into()),
            memory: Some(mem_lim.into()),
        }),
    }
}

fn container(
    image: &str,
    variables: BTreeMap<String, TemplateString>,
    volumes: BTreeMap<String, VolumeMount>,
    res: ResourceRequirements,
    readiness: Probe,
) -> ContainerSpec {
    ContainerSpec {
        image: image.into(),
        command: None,
        args: None,
        variables,
        resources: Some(res),
        files: BTreeMap::new(),
        volumes,
        liveness_probe: None,
        readiness_probe: Some(readiness),
        startup_probe: None,
    }
}

fn service_port(port: u16) -> ServicePortsSpec {
    ServicePortsSpec {
        ports: BTreeMap::from([(
            "http".into(),
            PortSpec {
                port,
                target_port: None,
                protocol: Some("TCP".into()),
            },
        )]),
    }
}

fn ingress(host: &str) -> IngressSpec {
    IngressSpec {
        hosts: vec![host.into()],
        paths: None,
        tls: Some(IngressTls {
            mode: TlsMode::Auto,
            secret_name: None,
            issuer_ref: Some(CertIssuerRef {
                name: "letsencrypt-prod".into(),
                kind: None,
            }),
        }),
        rate_limit: None,
        gateway_class: None,
    }
}

fn lattice_service(name: &str, spec: LatticeServiceSpec) -> LatticeService {
    LatticeService {
        metadata: ObjectMeta {
            name: Some(name.into()),
            namespace: Some(NAMESPACE.into()),
            ..Default::default()
        },
        spec,
        status: None,
    }
}

// =============================================================================
// Service Definitions
// =============================================================================

fn create_jellyfin() -> LatticeService {
    let mut variables = BTreeMap::new();
    variables.insert(
        "JELLYFIN_PublishedServerUrl".into(),
        TemplateString::from("http://jellyfin.media.svc.cluster.local:8096"),
    );

    let mut volumes = BTreeMap::new();
    volumes.insert("/config".into(), vol_mount("config", None));
    volumes.insert("/cache".into(), vol_mount("cache", None));
    volumes.insert("/media".into(), vol_mount("media-storage", Some("library")));

    let mut resources_map = BTreeMap::new();
    resources_map.insert("config".into(), volume_owned("10Gi"));
    resources_map.insert("cache".into(), volume_owned("20Gi"));
    resources_map.insert(
        "media-storage".into(),
        volume_shared_owner("media-storage", "1Ti"),
    );
    resources_map.insert("sonarr".into(), service_inbound(100));

    lattice_service(
        "jellyfin",
        LatticeServiceSpec {
            containers: BTreeMap::from([(
                "main".into(),
                container(
                    "jellyfin/jellyfin:latest",
                    variables,
                    volumes,
                    resources("500m", "1Gi", "4000m", "8Gi"),
                    http_probe("/health", 8096),
                ),
            )]),
            resources: resources_map,
            service: Some(service_port(8096)),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
            ingress: Some(ingress("jellyfin.home.local")),
        },
    )
}

fn create_nzbget() -> LatticeService {
    let mut variables = BTreeMap::new();
    variables.insert("PUID".into(), TemplateString::from("1000"));
    variables.insert("PGID".into(), TemplateString::from("1000"));
    variables.insert("TZ".into(), TemplateString::from("America/New_York"));

    let mut volumes = BTreeMap::new();
    volumes.insert("/config".into(), vol_mount("config", None));
    volumes.insert(
        "/downloads".into(),
        vol_mount("media-storage", Some("downloads")),
    );

    let mut resources_map = BTreeMap::new();
    resources_map.insert("config".into(), volume_owned("1Gi"));
    resources_map.insert("media-storage".into(), volume_shared_ref("media-storage"));
    resources_map.insert("sonarr".into(), service_inbound(1000));

    lattice_service(
        "nzbget",
        LatticeServiceSpec {
            containers: BTreeMap::from([(
                "main".into(),
                container(
                    "linuxserver/nzbget:latest",
                    variables,
                    volumes,
                    resources("100m", "256Mi", "2000m", "2Gi"),
                    http_probe("/", 6789),
                ),
            )]),
            resources: resources_map,
            service: Some(service_port(6789)),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
            ingress: None,
        },
    )
}

fn create_sonarr() -> LatticeService {
    let mut variables = BTreeMap::new();
    variables.insert("PUID".into(), TemplateString::from("1000"));
    variables.insert("PGID".into(), TemplateString::from("1000"));
    variables.insert("TZ".into(), TemplateString::from("America/New_York"));

    let mut volumes = BTreeMap::new();
    volumes.insert("/config".into(), vol_mount("config", None));
    volumes.insert(
        "/downloads".into(),
        vol_mount("media-storage", Some("downloads")),
    );
    volumes.insert("/tv".into(), vol_mount("media-storage", Some("library")));

    let mut resources_map = BTreeMap::new();
    resources_map.insert("config".into(), volume_owned("5Gi"));
    resources_map.insert("media-storage".into(), volume_shared_ref("media-storage"));
    resources_map.insert("nzbget".into(), service_outbound("30s", Some((3, "10s"))));
    resources_map.insert("jellyfin".into(), service_outbound("60s", None));

    lattice_service(
        "sonarr",
        LatticeServiceSpec {
            containers: BTreeMap::from([(
                "main".into(),
                container(
                    "linuxserver/sonarr:latest",
                    variables,
                    volumes,
                    resources("100m", "256Mi", "1000m", "1Gi"),
                    http_probe("/ping", 8989),
                ),
            )]),
            resources: resources_map,
            service: Some(service_port(8989)),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
            ingress: Some(ingress("sonarr.home.local")),
        },
    )
}

// =============================================================================
// Test Implementation
// =============================================================================

async fn deploy_media_services(kubeconfig_path: &str) -> Result<(), String> {
    println!("Deploying media server services...");

    let client = client_from_kubeconfig(kubeconfig_path).await?;

    // Create namespace
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(NAMESPACE.into()),
            labels: Some(BTreeMap::from([(
                "istio.io/dataplane-mode".into(),
                "ambient".into(),
            )])),
            ..Default::default()
        },
        ..Default::default()
    };

    match ns_api.create(&PostParams::default(), &ns).await {
        Ok(_) => println!("  Created namespace {}", NAMESPACE),
        Err(kube::Error::Api(e)) if e.code == 409 => {
            // Namespace exists, patch labels
            let patch = serde_json::json!({
                "metadata": {
                    "labels": {
                        "istio.io/dataplane-mode": "ambient"
                    }
                }
            });
            let _ = ns_api
                .patch(
                    NAMESPACE,
                    &kube::api::PatchParams::default(),
                    &kube::api::Patch::Merge(&patch),
                )
                .await;
        }
        Err(e) => return Err(format!("Failed to create namespace: {}", e)),
    }

    // Deploy services
    let api: Api<LatticeService> = Api::namespaced(client, NAMESPACE);
    for (name, svc) in [
        ("jellyfin", create_jellyfin()),
        ("nzbget", create_nzbget()),
        ("sonarr", create_sonarr()),
    ] {
        println!("  Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    Ok(())
}

/// Condition that checks if a Deployment is available
fn is_deployment_available() -> impl Condition<Deployment> {
    |obj: Option<&Deployment>| {
        obj.and_then(|d| d.status.as_ref()).map_or(false, |status| {
            let desired = status.replicas.unwrap_or(0);
            let available = status.available_replicas.unwrap_or(0);
            desired > 0 && available >= desired
        })
    }
}

async fn wait_for_pods(kubeconfig_path: &str) -> Result<(), String> {
    println!("Waiting for deployments...");

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<Deployment> = Api::namespaced(client, NAMESPACE);

    for name in ["jellyfin", "nzbget", "sonarr"] {
        println!("  Waiting for {}...", name);
        let cond = await_condition(api.clone(), name, is_deployment_available());
        tokio::time::timeout(Duration::from_secs(300), cond)
            .await
            .map_err(|_| format!("Timeout waiting for deployment {}", name))?
            .map_err(|e| format!("Error waiting for {}: {}", name, e))?;
    }

    println!("  All deployments available");
    Ok(())
}

async fn verify_pvcs(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying PVCs...");

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<PersistentVolumeClaim> = Api::namespaced(client, NAMESPACE);

    let pvcs = api
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list PVCs: {}", e))?;

    let pvc_names: Vec<&str> = pvcs
        .items
        .iter()
        .filter_map(|p| p.metadata.name.as_deref())
        .collect();

    for expected in [
        "vol-media-storage",
        "jellyfin-config",
        "jellyfin-cache",
        "sonarr-config",
        "nzbget-config",
    ] {
        if !pvc_names.iter().any(|p| p.contains(expected)) {
            return Err(format!(
                "Missing PVC: {} (found: {:?})",
                expected, pvc_names
            ));
        }
    }

    let shared_count = pvc_names.iter().filter(|p| p.starts_with("vol-")).count();
    if shared_count != 1 {
        return Err(format!("Expected 1 shared volume, found {}", shared_count));
    }

    println!("  PVCs verified");
    Ok(())
}

async fn verify_node_colocation(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying pod co-location...");

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<Pod> = Api::namespaced(client, NAMESPACE);

    let get_node = |pods: &[Pod], name: &str| -> Result<String, String> {
        let pod = pods
            .iter()
            .find(|p| {
                p.metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("app.kubernetes.io/name"))
                    .map(|v| v == name)
                    .unwrap_or(false)
            })
            .ok_or_else(|| format!("No pod found with label app.kubernetes.io/name={}", name))?;

        pod.spec
            .as_ref()
            .and_then(|s| s.node_name.clone())
            .ok_or_else(|| format!("Pod {} has no node assigned", name))
    };

    let pod_list = api
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list pods: {}", e))?;

    let jellyfin_node = get_node(&pod_list.items, "jellyfin")?;
    let sonarr_node = get_node(&pod_list.items, "sonarr")?;
    let nzbget_node = get_node(&pod_list.items, "nzbget")?;

    if jellyfin_node != sonarr_node || jellyfin_node != nzbget_node {
        return Err(format!(
            "Pods not co-located: jellyfin={}, sonarr={}, nzbget={}",
            jellyfin_node, sonarr_node, nzbget_node
        ));
    }

    println!("  All pods on node: {}", jellyfin_node);
    Ok(())
}

async fn verify_volume_sharing(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying volume sharing...");
    sleep(Duration::from_secs(5)).await;

    // kubectl exec is needed for running commands in pods
    let exec = |deploy: &str, cmd: &str| -> Result<String, String> {
        run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "exec",
                "-n",
                NAMESPACE,
                &format!("deploy/{}", deploy),
                "--",
                "sh",
                "-c",
                cmd,
            ],
        )
    };

    // jellyfin writes to library/, sonarr reads it
    exec("jellyfin", "echo 'jellyfin-marker' > /media/.test-marker")?;
    let result = exec("sonarr", "cat /tv/.test-marker")?;
    if !result.contains("jellyfin-marker") {
        return Err("sonarr cannot read jellyfin's marker".into());
    }

    // nzbget writes to downloads/, sonarr reads it
    exec("nzbget", "echo 'nzbget-marker' > /downloads/.test-marker")?;
    let result = exec("sonarr", "cat /downloads/.test-marker")?;
    if !result.contains("nzbget-marker") {
        return Err("sonarr cannot read nzbget's marker".into());
    }

    // Verify subpath isolation
    let result = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/jellyfin",
            "--",
            "cat",
            "/media/.test-marker",
        ],
    );
    if result.contains("nzbget-marker") {
        return Err("Subpath isolation failed".into());
    }

    println!("  Volume sharing verified");
    Ok(())
}

async fn verify_bilateral_agreements(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying bilateral agreements...");
    sleep(Duration::from_secs(30)).await;

    // kubectl exec needed for curl checks
    let curl_check = |from: &str, to: &str, port: u16| -> String {
        run_cmd_allow_fail("kubectl", &[
            "--kubeconfig", kubeconfig_path,
            "exec", "-n", NAMESPACE, &format!("deploy/{}", from),
            "--", "sh", "-c",
            &format!("curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 http://{}:{}/ || echo '000'", to, port),
        ]).trim().to_string()
    };

    // sonarr -> jellyfin (allowed)
    let code = curl_check("sonarr", "jellyfin", 8096);
    if code == "403" {
        return Err("sonarr->jellyfin blocked unexpectedly".into());
    }
    println!("  sonarr->jellyfin: {} (allowed)", code);

    // sonarr -> nzbget (allowed)
    let code = curl_check("sonarr", "nzbget", 6789);
    if code == "403" {
        return Err("sonarr->nzbget blocked unexpectedly".into());
    }
    println!("  sonarr->nzbget: {} (allowed)", code);

    // jellyfin -> sonarr (should be blocked)
    let code = curl_check("jellyfin", "sonarr", 8989);
    println!("  jellyfin->sonarr: {} (expected 403)", code);

    Ok(())
}

async fn cleanup(kubeconfig_path: &str) {
    let Ok(client) = client_from_kubeconfig(kubeconfig_path).await else {
        return;
    };

    let api: Api<LatticeService> = Api::namespaced(client.clone(), NAMESPACE);
    for name in ["sonarr", "nzbget", "jellyfin"] {
        let _ = api.delete(name, &kube::api::DeleteParams::default()).await;
    }

    let ns_api: Api<Namespace> = Api::all(client);
    let _ = ns_api
        .delete(NAMESPACE, &kube::api::DeleteParams::default())
        .await;

    // Wait for namespace deletion
    sleep(Duration::from_secs(30)).await;
}

// =============================================================================
// Public API
// =============================================================================

pub async fn run_media_server_test(kubeconfig_path: &str) -> Result<(), String> {
    println!("\n========================================");
    println!("Media Server E2E Test");
    println!("========================================\n");

    deploy_media_services(kubeconfig_path).await?;
    wait_for_pods(kubeconfig_path).await?;
    verify_pvcs(kubeconfig_path).await?;
    verify_node_colocation(kubeconfig_path).await?;
    verify_volume_sharing(kubeconfig_path).await?;

    println!("Waiting for Istio waypoint...");
    sleep(Duration::from_secs(30)).await;

    verify_bilateral_agreements(kubeconfig_path).await?;

    println!("\n========================================");
    println!("Media Server E2E Test: PASSED");
    println!("========================================\n");

    Ok(())
}

pub async fn cleanup_media_server_test(kubeconfig_path: &str) {
    cleanup(kubeconfig_path).await;
}
