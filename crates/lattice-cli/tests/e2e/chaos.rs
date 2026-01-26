//! Chaos monkey for E2E tests - randomly kills pods and cuts network to test resilience

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use rand::Rng;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::helpers::run_cmd_allow_fail;

const OPERATOR_NS: &str = "lattice-system";
const OPERATOR_LABEL: &str = "app=lattice-operator";

/// Configuration for chaos monkey behavior
#[derive(Clone, Copy)]
pub struct ChaosConfig {
    /// Min/max seconds between pod kills
    pub pod_interval: (u64, u64),
    /// Min/max seconds between network cuts
    pub net_interval: (u64, u64),
    /// Duration of network blackouts in seconds
    pub net_blackout_secs: u64,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            pod_interval: (30, 90),
            net_interval: (60, 120),
            net_blackout_secs: 3,
        }
    }
}

impl ChaosConfig {
    /// Aggressive chaos settings for endurance testing
    /// Pod kills every 30-60s, network cuts every 45-90s for 3s
    /// Still stressful but allows reconciliation loops to complete
    pub fn aggressive() -> Self {
        Self {
            pod_interval: (30, 60),
            net_interval: (45, 90),
            net_blackout_secs: 3,
        }
    }
}

const NETWORK_BLACKOUT_POLICY: &str = r#"apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: chaos-blackout
  namespace: lattice-system
spec:
  endpointSelector:
    matchLabels:
      app: lattice-operator
  ingressDeny:
    - fromEntities: [all]
  egressDeny:
    - toEntities: [all]
"#;

/// Cluster targets for chaos testing
pub struct ChaosTargets(RwLock<Vec<(String, String)>>);

impl ChaosTargets {
    pub fn new() -> Self {
        Self(RwLock::new(Vec::new()))
    }

    pub fn add(&self, name: &str, kubeconfig: &str) {
        let mut targets = self.0.write();
        if !targets.iter().any(|(n, _)| n == name) {
            info!("[Chaos] Target added: {}", name);
            targets.push((name.to_string(), kubeconfig.to_string()));
        }
    }

    fn random(&self) -> Option<(String, String)> {
        let targets = self.0.read();
        if targets.is_empty() {
            return None;
        }
        let idx = rand::thread_rng().gen_range(0..targets.len());
        Some(targets[idx].clone())
    }
}

pub struct ChaosMonkey {
    pod_task: tokio::task::JoinHandle<()>,
    net_task: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
}

impl ChaosMonkey {
    /// Start chaos monkey with default configuration
    pub fn start(targets: Arc<ChaosTargets>) -> Self {
        Self::start_with_config(targets, ChaosConfig::default())
    }

    /// Start chaos monkey with custom configuration
    pub fn start_with_config(targets: Arc<ChaosTargets>, config: ChaosConfig) -> Self {
        info!(
            "[Chaos] Started (pod kills: {}-{}s, network cuts: {}-{}s for {}s)",
            config.pod_interval.0,
            config.pod_interval.1,
            config.net_interval.0,
            config.net_interval.1,
            config.net_blackout_secs
        );

        let cancel = CancellationToken::new();

        let pod_task = tokio::spawn(pod_chaos_loop(
            targets.clone(),
            cancel.clone(),
            config.pod_interval,
        ));
        let net_task = tokio::spawn(net_chaos_loop(
            targets,
            cancel.clone(),
            config.net_interval,
            config.net_blackout_secs,
        ));

        Self {
            pod_task,
            net_task,
            cancel,
        }
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        self.pod_task.abort();
        self.net_task.abort();
        info!("[Chaos] Stopped");
    }
}

async fn pod_chaos_loop(
    targets: Arc<ChaosTargets>,
    cancel: CancellationToken,
    interval: (u64, u64),
) {
    loop {
        let delay = rand::thread_rng().gen_range(interval.0..=interval.1);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
        }
        if let Some((name, kubeconfig)) = targets.random() {
            kill_pod(&name, &kubeconfig);
        }
    }
}

async fn net_chaos_loop(
    targets: Arc<ChaosTargets>,
    cancel: CancellationToken,
    interval: (u64, u64),
    blackout_secs: u64,
) {
    loop {
        let delay = rand::thread_rng().gen_range(interval.0..=interval.1);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
        }
        if let Some((name, kubeconfig)) = targets.random() {
            cut_network(&name, &kubeconfig, &cancel, blackout_secs).await;
        }
    }
}

fn kill_pod(cluster: &str, kubeconfig: &str) {
    let output = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "pod",
            "-n",
            OPERATOR_NS,
            "-l",
            OPERATOR_LABEL,
            "--wait=false",
        ],
    );

    let msg = if output.contains("deleted") {
        "killed"
    } else if output.contains("No resources found") {
        "no pod (restarting)"
    } else if is_unreachable(&output) {
        "unreachable"
    } else {
        output.trim()
    };
    info!("[Chaos] Pod on {}: {}", cluster, msg);
}

async fn cut_network(
    cluster: &str,
    kubeconfig: &str,
    cancel: &CancellationToken,
    blackout_secs: u64,
) {
    let policy_file = format!("/tmp/chaos-{}.yaml", cluster);

    // Apply blackout policy
    if std::fs::write(&policy_file, NETWORK_BLACKOUT_POLICY).is_err() {
        return;
    }

    let output = run_cmd_allow_fail(
        "kubectl",
        &["--kubeconfig", kubeconfig, "apply", "-f", &policy_file],
    );

    if !output.contains("created") && !output.contains("configured") {
        let _ = std::fs::remove_file(&policy_file);
        if !is_unreachable(&output) {
            info!("[Chaos] Network on {}: {}", cluster, output.trim());
        }
        return;
    }

    info!("[Chaos] Network on {}: cut for {}s", cluster, blackout_secs);

    // Wait for blackout (but respect cancellation)
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = tokio::time::sleep(Duration::from_secs(blackout_secs)) => {}
    }

    // Always restore network
    run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "-f",
            &policy_file,
            "--ignore-not-found",
        ],
    );
    let _ = std::fs::remove_file(&policy_file);
    info!("[Chaos] Network on {}: restored", cluster);
}

fn is_unreachable(output: &str) -> bool {
    output.contains("refused") || output.contains("unreachable") || output.contains("no such host")
}
