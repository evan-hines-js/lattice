//! Render the Tetragon helm chart into `$OUT_DIR/tetragon.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions().expect("read versions.toml");
    let chart = versions
        .charts
        .get("tetragon")
        .expect("versions.toml missing [charts.tetragon]");
    let chart_path =
        lattice_helm_build::ensure_chart("tetragon", chart).expect("ensure tetragon chart");

    // `crds.installMethod=helm` renders TracingPolicy/TracingPolicyNamespaced
    // CRDs inline. Tetragon's default ("operator") defers CRD creation to the
    // tetragon-operator pod, which races with TracingPolicies applied
    // immediately after install.
    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "tetragon",
        "kube-system",
        &[
            "--set",
            "tetragon.enablePolicyFilter=true",
            "--set",
            "tetragon.enablePolicyFilterDebug=false",
            "--set",
            "rthooks.enabled=false",
            "--set",
            "crds.installMethod=helm",
        ],
    )
    .expect("render tetragon chart");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("tetragon.yaml"), yaml).expect("write tetragon.yaml");

    println!("cargo:rustc-env=TETRAGON_VERSION={}", chart.version);
}
