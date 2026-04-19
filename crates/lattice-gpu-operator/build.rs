//! Render the NVIDIA GPU Operator helm chart into `$OUT_DIR/gpu-operator.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions();
    let chart = versions
        .charts
        .get("gpu-operator")
        .expect("versions.toml missing [charts.gpu-operator]");
    // The NVIDIA chart artifact names the tarball with a `v` prefix: `gpu-operator-vX.Y.Z.tgz`.
    let chart_path = lattice_helm_build::ensure_chart("gpu-operator", chart);

    // driver.enabled=false: Lattice assumes drivers are installed out-of-band
    // (most datacentre GPU images ship them). toolkit + device plugin + NFD +
    // DCGM exporter + GFD turn on the observability/scheduling surface; MIG
    // manager stays off until we expose MIG config in LatticeService.
    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "gpu-operator",
        "gpu-operator",
        &[
            "--set",
            "driver.enabled=false",
            "--set",
            "toolkit.enabled=true",
            "--set",
            "devicePlugin.enabled=true",
            "--set",
            "nfd.enabled=true",
            "--set",
            "dcgmExporter.enabled=true",
            "--set",
            "migManager.enabled=false",
            "--set",
            "gfd.enabled=true",
        ],
    );

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("gpu-operator.yaml"), yaml).expect("write gpu-operator.yaml");

    println!("cargo:rustc-env=GPU_OPERATOR_VERSION={}", chart.version);
}
