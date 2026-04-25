//! Render the Cilium helm chart into `$OUT_DIR/cilium.yaml`.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions();
    let chart = versions
        .charts
        .get("cilium")
        .expect("versions.toml missing [charts.cilium]");
    let chart_path = lattice_helm_build::ensure_chart("cilium", chart);

    // Native routing + BGP control-plane: Pod traffic is routed over
    // the underlay; PodCIDR /24s and Service LoadBalancer /32s are
    // advertised via iBGP from each node. CNI shared with istio-cni.
    // L2 announcements stay enabled for non-basis providers (Docker,
    // Proxmox) that opt into Cilium L2 LB-IPAM via per-cluster CRDs.
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
            "kubeProxyReplacement=true",
            // Istio ambient compatibility: scope Cilium's socket LB to the
            // host namespace only, so Pod-egress traffic still falls through
            // to ztunnel's iptables redirection. Without this, socket LB
            // rewrites the destination inside the Pod's socket namespace
            // before iptables can match — bypassing the mesh entirely.
            // See: https://docs.cilium.io/en/stable/network/servicemesh/istio/
            "--set",
            "socketLB.hostNamespaceOnly=true",
            "--set",
            "l2announcements.enabled=true",
            "--set",
            "externalIPs.enabled=true",
            "--set",
            "hostFirewall.enabled=false",
            "--set",
            "routingMode=native",
            "--set",
            "ipv4NativeRoutingCIDR=10.0.0.0/8",
            "--set",
            "autoDirectNodeRoutes=false",
            "--set",
            "bgpControlPlane.enabled=true",
            "--set",
            "ipam.mode=kubernetes",
            "--set",
            "bpf.masquerade=true",
            // DSR: backend pods reply directly to clients; preserves source
            // IP and skips the return hop through the LB-selected node. The
            // iBGP /32 underlay every node advertises is what makes this
            // work — return paths are already legitimate from any node.
            "--set",
            "loadBalancer.mode=dsr",
            "--set",
            "loadBalancer.acceleration=disabled",
            "--set-string",
            "k8sServiceHost=__LATTICE_API_SERVER_HOST__",
            "--set-string",
            "k8sServicePort=__LATTICE_API_SERVER_PORT__",
        ],
    );

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("cilium.yaml"), yaml).expect("write cilium.yaml");

    println!("cargo:rustc-env=CILIUM_VERSION={}", chart.version);
}
