//! Render the cert-manager helm chart into `$OUT_DIR/cert-manager.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions().expect("read versions.toml");
    let chart = versions
        .charts
        .get("cert-manager")
        .expect("versions.toml missing [charts.cert-manager]");
    let chart_path =
        lattice_helm_build::ensure_chart("cert-manager", chart).expect("ensure cert-manager chart");

    // CRDs rendered inline + control-plane tolerations across every cert-manager
    // workload so they can schedule on kubeadm-tainted CP nodes before workers exist.
    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "cert-manager",
        "cert-manager",
        &[
            "--set",
            "crds.enabled=true",
            "--set",
            "tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "tolerations[0].operator=Exists",
            "--set",
            "tolerations[0].effect=NoSchedule",
            "--set",
            "webhook.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "webhook.tolerations[0].operator=Exists",
            "--set",
            "webhook.tolerations[0].effect=NoSchedule",
            "--set",
            "cainjector.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "cainjector.tolerations[0].operator=Exists",
            "--set",
            "cainjector.tolerations[0].effect=NoSchedule",
            "--set",
            "startupapicheck.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "startupapicheck.tolerations[0].operator=Exists",
            "--set",
            "startupapicheck.tolerations[0].effect=NoSchedule",
        ],
    )
    .expect("render cert-manager chart");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("cert-manager.yaml"), yaml).expect("write cert-manager.yaml");

    println!("cargo:rustc-env=CERT_MANAGER_VERSION={}", chart.version);
}
