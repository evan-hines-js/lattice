//! Render the Cilium helm chart into `$OUT_DIR/cilium.yaml`.
//!
//! Toggle `KUBE_PROXY_REPLACEMENT` to switch between Cilium's eBPF kube-proxy
//! replacement and stock kube-proxy (kubeadm addon). The flag is mirrored at
//! runtime via `kube_proxy_replacement.rs` so `lattice-capi` can decide
//! whether to skip the kube-proxy phase during init.

use std::path::PathBuf;

/// Compile-time switch.
///
/// `false` — kubeadm installs kube-proxy as usual; Cilium runs as a plain CNI.
/// `true`  — Cilium's eBPF kube-proxy replacement; kubeadm skips the addon.
const KUBE_PROXY_REPLACEMENT: bool = true;

fn main() {
    let versions = lattice_helm_build::read_versions().expect("read versions.toml");
    let chart = versions
        .charts
        .get("cilium")
        .expect("versions.toml missing [charts.cilium]");
    let chart_path =
        lattice_helm_build::ensure_chart("cilium", chart).expect("ensure cilium chart");

    let mut args: Vec<&str> = vec![
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
        "l2announcements.enabled=true",
        "--set",
        "externalIPs.enabled=true",
        "--set",
        "hostFirewall.enabled=false",
        "--set",
        "routingMode=native",
        // Native routing skips masquerade for destinations inside
        // this CIDR — must be exactly the cluster's pod CIDR.
        // Setting it wider (e.g. 10.0.0.0/8) lets pod traffic
        // egress with pod-IP source to LAN destinations and the
        // upstream router drops the reply because pod CIDR isn't
        // routable. Substituted at install time per cluster from
        // `clusterNetwork.pods.cidrBlocks[0]`.
        "--set",
        "ipv4NativeRoutingCIDR=__LATTICE_POD_CIDR__",
        // basis tree VXLAN gives every k8s node a flat L2 inside the
        // cluster, so Cilium can install per-node pod-CIDR routes
        // (`192.168.<n>.0/24 via <node-IP>`) without a second
        // encap. Pushing tunneling into Cilium would clash with
        // basis's UDP/4789 + FORWARD spoof-guard and waste MTU
        // double-encapping every pod packet.
        "--set",
        "autoDirectNodeRoutes=true",
        "--set",
        "bgpControlPlane.enabled=false",
        "--set",
        "ipam.mode=kubernetes",
    ];

    if KUBE_PROXY_REPLACEMENT {
        // Native routing for pod traffic. CNI shared with istio-cni.
        // L2 announcements drive LB-IPAM (Cilium gARPs assigned IPs on
        // node interfaces). External advertisement of cluster VIPs is
        // basis's job, not Cilium's — `bgpControlPlane.enabled=false`.
        args.extend([
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
            "bpf.masquerade=false",
            // DSR: backend pods reply directly to clients; preserves
            // source IP and skips the return hop through the
            // LB-selected node.
            "--set",
            "loadBalancer.mode=dsr",
            "--set",
            "loadBalancer.acceleration=disabled",
            "--set-string",
            "k8sServiceHost=__LATTICE_API_SERVER_HOST__",
            "--set-string",
            "k8sServicePort=__LATTICE_API_SERVER_PORT__",
        ]);
    } else {
        // Stock kube-proxy mode: explicitly disable Cilium's replacement so
        // chart defaults can't drift onto kPR. Source IP preservation now
        // depends on `externalTrafficPolicy: Local` per Service rather than
        // DSR.
        args.extend(["--set", "kubeProxyReplacement=false"]);
    }

    let yaml = lattice_helm_build::render_chart(&chart_path, "cilium", "kube-system", &args)
        .expect("render cilium chart");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("cilium.yaml"), yaml).expect("write cilium.yaml");
    std::fs::write(
        out_dir.join("kube_proxy_replacement.rs"),
        format!("pub const KUBE_PROXY_REPLACEMENT: bool = {KUBE_PROXY_REPLACEMENT};\n"),
    )
    .expect("write kube_proxy_replacement.rs");

    println!("cargo:rustc-env=CILIUM_VERSION={}", chart.version);
}
