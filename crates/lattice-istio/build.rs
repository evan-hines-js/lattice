//! Render the four Istio ambient charts into `$OUT_DIR`:
//! `istio-base.yaml`, `istio-cni.yaml`, `istiod.yaml`, `ztunnel.yaml`.
//!
//! `istiod.yaml` and `ztunnel.yaml` contain placeholder tokens
//! (`__LATTICE_CLUSTER_NAME__`, `__LATTICE_TRUST_DOMAIN__`,
//! `__LATTICE_MESH_NETWORKS__`) that the controller substitutes at apply time
//! with per-cluster values derived from `lattice-ca` + `LatticeClusterRoutes`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions();
    let istio_version = versions
        .charts
        .get("istio-base")
        .expect("versions.toml missing [charts.istio-base]")
        .version
        .clone();

    let base_path = lattice_helm_build::ensure_chart(
        "istio-base",
        versions.charts.get("istio-base").expect("istio-base chart"),
    );
    let cni_path = lattice_helm_build::ensure_chart(
        "istio-cni",
        versions.charts.get("istio-cni").expect("istio-cni chart"),
    );
    let istiod_path = lattice_helm_build::ensure_chart(
        "istiod",
        versions.charts.get("istiod").expect("istiod chart"),
    );
    let ztunnel_path = lattice_helm_build::ensure_chart(
        "ztunnel",
        versions.charts.get("ztunnel").expect("ztunnel chart"),
    );

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));

    let base = lattice_helm_build::render_chart(&base_path, "istio-base", "istio-system", &[]);
    std::fs::write(out_dir.join("istio-base.yaml"), base).expect("write istio-base.yaml");

    let cni = lattice_helm_build::render_chart(
        &cni_path,
        "istio-cni",
        "istio-system",
        &[
            "--set", "profile=ambient",
            "--set", "cni.cniConfFileName=05-cilium.conflist",
        ],
    );
    std::fs::write(out_dir.join("istio-cni.yaml"), cni).expect("write istio-cni.yaml");

    // istiod carries cluster-specific values (trust domain, meshID, network,
    // meshNetworks). `AMBIENT_ENABLE_BAGGAGE` is intentionally disabled —
    // enabling it causes 502s via missing upstream `peer_metadata` filter
    // (upstream issue: istio/istio#59117).
    let istiod = lattice_helm_build::render_chart(
        &istiod_path,
        "istiod",
        "istio-system",
        &[
            "--set", "profile=ambient",
            "--set", "meshConfig.trustDomain=__LATTICE_TRUST_DOMAIN__",
            "--set", "global.meshID=lattice-mesh",
            "--set", "global.multiCluster.clusterName=__LATTICE_CLUSTER_NAME__",
            "--set", "global.network=__LATTICE_CLUSTER_NAME__",
            "--set-json",
            r#"global.meshNetworks={"__LATTICE_MESH_NETWORKS__":"__LATTICE_MESH_NETWORKS__"}"#,
            "--set", "env.AMBIENT_ENABLE_MULTI_NETWORK=true",
            "--set", "env.AMBIENT_ENABLE_MULTI_NETWORK_INGRESS=true",
            "--set", "pilot.resources.requests.cpu=100m",
            "--set", "pilot.resources.requests.memory=128Mi",
            "--set", "pilot.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set", "pilot.tolerations[0].operator=Exists",
            "--set", "pilot.tolerations[0].effect=NoSchedule",
        ],
    );
    std::fs::write(out_dir.join("istiod.yaml"), istiod).expect("write istiod.yaml");

    let ztunnel = lattice_helm_build::render_chart(
        &ztunnel_path,
        "ztunnel",
        "istio-system",
        &[
            "--set", "multiCluster.clusterName=__LATTICE_CLUSTER_NAME__",
            "--set", "global.network=__LATTICE_CLUSTER_NAME__",
        ],
    );
    std::fs::write(out_dir.join("ztunnel.yaml"), ztunnel).expect("write ztunnel.yaml");

    println!("cargo:rustc-env=ISTIO_VERSION={}", istio_version);
}
