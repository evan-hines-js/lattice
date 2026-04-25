//! Render the Velero helm chart into `$OUT_DIR/velero.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions().expect("read versions.toml");
    let chart = versions
        .charts
        .get("velero")
        .expect("versions.toml missing [charts.velero]");
    let chart_path =
        lattice_helm_build::ensure_chart("velero", chart).expect("ensure velero chart");

    // Node agent + snapshots + AWS plugin init container baked in. Empty
    // `backupStorageLocation` / `volumeSnapshotLocation` so chart hooks don't
    // try to validate non-existent buckets — BackupStore reconciliation
    // populates those at runtime.
    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "velero",
        "velero",
        &[
            "--set",
            "deployNodeAgent=true",
            "--set",
            "snapshotsEnabled=true",
            "--set",
            "initContainers[0].name=velero-plugin-for-aws",
            "--set",
            "initContainers[0].image=velero/velero-plugin-for-aws:v1.13.0",
            "--set",
            "initContainers[0].imagePullPolicy=IfNotPresent",
            "--set",
            "initContainers[0].volumeMounts[0].mountPath=/target",
            "--set",
            "initContainers[0].volumeMounts[0].name=plugins",
            "--set",
            "upgradeCRDs=false",
            "--set-json",
            "configuration.backupStorageLocation=[]",
            "--set-json",
            "configuration.volumeSnapshotLocation=[]",
        ],
    )
    .expect("render velero chart");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("velero.yaml"), yaml).expect("write velero.yaml");

    println!("cargo:rustc-env=VELERO_VERSION={}", chart.version);
}
