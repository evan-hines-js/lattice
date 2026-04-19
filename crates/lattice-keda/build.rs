//! Render the KEDA helm chart into `$OUT_DIR/keda.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions();
    let chart = versions
        .charts
        .get("keda")
        .expect("versions.toml missing [charts.keda]");
    let chart_path = lattice_helm_build::ensure_chart("keda", chart);

    // Control-plane tolerations on the operator + webhooks + metrics server so
    // they can schedule on kubeadm-tainted CP nodes before workers exist.
    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "keda",
        "keda",
        &[
            "--set",
            "tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "tolerations[0].operator=Exists",
            "--set",
            "tolerations[0].effect=NoSchedule",
            "--set",
            "webhooks.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "webhooks.tolerations[0].operator=Exists",
            "--set",
            "webhooks.tolerations[0].effect=NoSchedule",
            "--set",
            "metricsServer.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "metricsServer.tolerations[0].operator=Exists",
            "--set",
            "metricsServer.tolerations[0].effect=NoSchedule",
        ],
    );

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("keda.yaml"), yaml).expect("write keda.yaml");

    println!("cargo:rustc-env=KEDA_VERSION={}", chart.version);
}
