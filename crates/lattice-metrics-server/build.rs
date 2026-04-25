//! Render the metrics-server helm chart into `$OUT_DIR/metrics-server.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions().expect("read versions.toml");
    let chart = versions
        .charts
        .get("metrics-server")
        .expect("versions.toml missing [charts.metrics-server]");
    let chart_path = lattice_helm_build::ensure_chart("metrics-server", chart)
        .expect("ensure metrics-server chart");

    // --kubelet-insecure-tls: kubeadm-provisioned kubelets serve on
    // self-signed certs by default; metrics-server would otherwise fail
    // the TLS handshake and mark every node unavailable.
    //
    // Control-plane tolerations so the pod schedules on kubeadm-tainted CP
    // nodes before workers exist.
    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "metrics-server",
        "kube-system",
        &[
            "--set",
            "args={--kubelet-insecure-tls}",
            "--set",
            "tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "tolerations[0].operator=Exists",
            "--set",
            "tolerations[0].effect=NoSchedule",
        ],
    )
    .expect("render metrics-server chart");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("metrics-server.yaml"), yaml).expect("write metrics-server.yaml");

    println!("cargo:rustc-env=METRICS_SERVER_VERSION={}", chart.version);
}
