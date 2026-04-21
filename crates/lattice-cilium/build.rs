//! Render the Cilium helm chart into `$OUT_DIR/cilium.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions();
    let chart = versions
        .charts
        .get("cilium")
        .expect("versions.toml missing [charts.cilium]");
    let chart_path = lattice_helm_build::ensure_chart("cilium", chart);

    // Values: Hubble disabled, Prometheus integration disabled, CNI shared with
    // istio-cni (exclusive=false), kubeProxyReplacement off, L2 announcements
    // + externalIPs on for on-prem LB-IPAM, host firewall off, VXLAN tunnel,
    // MTU accommodates VXLAN overhead, kubernetes IPAM, BPF masquerade off,
    // legacy host routing to cooperate with istio-cni chaining.
    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "cilium",
        "kube-system",
        &[
            "--set",
            "hubble.enabled=false",
            "--set",
            "hubble.relay.enabled=false",
            "--set",
            "hubble.ui.enabled=false",
            "--set",
            "prometheus.enabled=false",
            "--set",
            "operator.prometheus.enabled=false",
            "--set",
            "cni.exclusive=false",
            "--set",
            "kubeProxyReplacement=false",
            "--set",
            "l2announcements.enabled=true",
            "--set",
            "externalIPs.enabled=true",
            "--set",
            "hostFirewall.enabled=false",
            "--set",
            "routingMode=tunnel",
            "--set",
            "tunnelProtocol=vxlan",
            "--set",
            "mtu=1450",
            "--set",
            "ipam.mode=kubernetes",
            "--set",
            "bpf.masquerade=false",
            "--set",
            "bpf.hostLegacyRouting=true",
        ],
    );

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("cilium.yaml"), yaml).expect("write cilium.yaml");

    println!("cargo:rustc-env=CILIUM_VERSION={}", chart.version);
}
