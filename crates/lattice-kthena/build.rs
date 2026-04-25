//! Render the Kthena helm chart into `$OUT_DIR/kthena.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions().expect("read versions.toml");
    let chart = versions
        .charts
        .get("kthena")
        .expect("versions.toml missing [charts.kthena]");
    let chart_path =
        lattice_helm_build::ensure_chart("kthena", chart).expect("ensure kthena chart");

    // cert-manager mode so the webhook certs are issued through Lattice's CA
    // rather than the chart's default helm-hook self-signer.
    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "kthena",
        "kthena-system",
        &[
            "--set",
            "controller.replicas=1",
            "--set",
            "router.replicas=1",
            "--set",
            "global.certManagementMode=cert-manager",
        ],
    )
    .expect("render kthena chart");

    // Upstream chart bug: the mutating-webhook annotation references
    // `kthena-webhook-cert`, but the actual Certificate resource is named
    // `kthena-controller-manager-webhook-cert`. Patch before embedding.
    let yaml = yaml.replace(
        "kthena-system/kthena-webhook-cert",
        "kthena-system/kthena-controller-manager-webhook-cert",
    );

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("kthena.yaml"), yaml).expect("write kthena.yaml");

    println!("cargo:rustc-env=KTHENA_VERSION={}", chart.version);
}
