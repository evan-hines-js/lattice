//! Render the External Secrets Operator helm chart into `$OUT_DIR/eso.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions();
    let chart = versions
        .charts
        .get("external-secrets")
        .expect("versions.toml missing [charts.external-secrets]");
    let chart_path = lattice_helm_build::ensure_chart("external-secrets", chart);

    // Render with CRDs inlined (installCRDs=true) and control-plane tolerations
    // so ESO schedules on the tainted control-plane nodes of kubeadm clusters.
    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "external-secrets",
        "external-secrets",
        &[
            "--set",
            "installCRDs=true",
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
            "certController.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "certController.tolerations[0].operator=Exists",
            "--set",
            "certController.tolerations[0].effect=NoSchedule",
        ],
    );

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("eso.yaml"), yaml).expect("write eso.yaml");

    println!("cargo:rustc-env=EXTERNAL_SECRETS_VERSION={}", chart.version);
}
