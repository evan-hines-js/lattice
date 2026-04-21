//! Render the victoria-metrics-k8s-stack chart twice — once for HA
//! (VMCluster with 2 replicas each), once for single-node (VMSingle).
//! Clusters opt into HA via `LatticeCluster.spec.monitoring.ha`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions();
    let chart = versions
        .charts
        .get("victoria-metrics-k8s-stack")
        .expect("versions.toml missing [charts.victoria-metrics-k8s-stack]");
    let chart_path = lattice_helm_build::ensure_chart("victoria-metrics-k8s-stack", chart);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));

    // HA: VMCluster (vmstorage/vmselect/vminsert × 2) with replicationFactor 2.
    let ha = lattice_helm_build::render_chart(
        &chart_path,
        "vm",
        "monitoring",
        &[
            "--set",
            "fullnameOverride=lattice-metrics",
            "--set",
            "vmcluster.enabled=true",
            "--set",
            "vmcluster.spec.retentionPeriod=24h",
            "--set",
            "vmcluster.spec.vmstorage.replicaCount=2",
            "--set",
            "vmcluster.spec.vmselect.replicaCount=2",
            "--set",
            "vmcluster.spec.vminsert.replicaCount=2",
            "--set",
            "vmcluster.spec.replicationFactor=2",
            "--set",
            "vmsingle.enabled=false",
            "--set",
            "grafana.enabled=false",
            "--set",
            "alertmanager.enabled=false",
            "--set",
            "vmalert.enabled=false",
        ],
    );
    std::fs::write(out_dir.join("victoria-metrics-ha.yaml"), ha)
        .expect("write victoria-metrics-ha.yaml");

    // Single-node: VMSingle, no replication.
    let single = lattice_helm_build::render_chart(
        &chart_path,
        "vm",
        "monitoring",
        &[
            "--set",
            "fullnameOverride=lattice-metrics",
            "--set",
            "vmcluster.enabled=false",
            "--set",
            "vmsingle.enabled=true",
            "--set",
            "vmsingle.spec.retentionPeriod=24h",
            "--set",
            "grafana.enabled=false",
            "--set",
            "alertmanager.enabled=false",
            "--set",
            "vmalert.enabled=false",
        ],
    );
    std::fs::write(out_dir.join("victoria-metrics-single.yaml"), single)
        .expect("write victoria-metrics-single.yaml");

    println!("cargo:rustc-env=VICTORIA_METRICS_VERSION={}", chart.version);
}
