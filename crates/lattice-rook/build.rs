//! Render the rook-ceph operator chart.
//!
//! Values picked for a lean production install: RBD CSI only (no CephFS,
//! no NFS), discovery daemon on, chart-side monitoring off (Lattice wires
//! ServiceMonitors via `lattice-victoria-metrics`). The CephCluster /
//! CephBlockPool / StorageClass are not rendered here — they depend on
//! `RookInstallSpec` and are generated at reconcile time.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions();
    let chart = versions
        .charts
        .get("rook-ceph")
        .expect("versions.toml missing [charts.rook-ceph]");
    let chart_path = lattice_helm_build::ensure_chart("rook-ceph", chart);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));

    let operator = lattice_helm_build::render_chart(
        &chart_path,
        "rook-ceph",
        "rook-ceph",
        &[
            "--set", "crds.enabled=true",
            "--set", "enableDiscoveryDaemon=true",
            "--set", "monitoring.enabled=false",
            // RBD only — CephFS + NFS are out of scope for Phase 1.
            "--set", "csi.enableRbdDriver=true",
            "--set", "csi.enableCephfsDriver=false",
            "--set", "csi.enableNFSDriver=false",
            "--set", "csi.cephFSSupport=false",
            // HA CSI provisioners.
            "--set", "csi.provisionerReplicas=2",
            // Operator Deployment resources — a 1-vCPU / 512 MiB request
            // keeps bin-packing honest without starving the controller.
            "--set", "resources.requests.cpu=500m",
            "--set", "resources.requests.memory=512Mi",
            "--set", "resources.limits.cpu=1",
            "--set", "resources.limits.memory=1Gi",
        ],
    );
    std::fs::write(out_dir.join("rook-operator.yaml"), operator)
        .expect("write rook-operator.yaml");

    println!("cargo:rustc-env=ROOK_CEPH_VERSION={}", chart.version);
}
