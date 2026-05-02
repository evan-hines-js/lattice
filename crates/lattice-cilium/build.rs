//! Render the Cilium helm chart into two outputs in `$OUT_DIR`:
//!
//!   * `cilium-l2.yaml` — `l2announcements.enabled=true`,
//!     `loadBalancer.mode=snat`. Used for providers without a BGP
//!     fabric (Proxmox, Docker, kind).
//!   * `cilium-bgp.yaml` — `bgpControlPlane.enabled=true`,
//!     `loadBalancer.mode=dsr`, `loadBalancer.dsrDispatch=geneve`.
//!     Used for the basis provider, which already runs an iBGP route
//!     reflector on basis-controller; k8s nodes peer with it as
//!     additional clients.
//!
//! Both variants share the kube-proxy-replacement / native-routing /
//! ambient-compat config; only the LB advertisement plane differs.
//!
//! Toggle `KUBE_PROXY_REPLACEMENT` to switch between Cilium's eBPF
//! kube-proxy replacement and stock kube-proxy (kubeadm addon). The
//! flag is mirrored at runtime via `kube_proxy_replacement.rs` so
//! `lattice-capi` can decide whether to skip the kube-proxy phase
//! during init.

use std::path::PathBuf;

/// Compile-time switch.
///
/// `false` — kubeadm installs kube-proxy as usual; Cilium runs as a plain CNI.
/// `true`  — Cilium's eBPF kube-proxy replacement; kubeadm skips the addon.
const KUBE_PROXY_REPLACEMENT: bool = true;

/// LB advertisement plane the variant is rendered for. Drives the
/// per-variant `--set` flags below.
#[derive(Copy, Clone)]
enum LbMode {
    /// L2-announce + SNAT. Single elected node gARPs each LB IP and
    /// SNAT'd traffic returns through that node. The right shape when
    /// no BGP fabric is available.
    L2,
    /// BGP-announce + DSR. Every node advertises LB pool /32s as iBGP
    /// routes; ECMP across announcers; backends DSR replies directly.
    /// Requires a route reflector (basis-controller embeds one).
    Bgp,
}

impl LbMode {
    fn out_file(self) -> &'static str {
        match self {
            Self::L2 => "cilium-l2.yaml",
            Self::Bgp => "cilium-bgp.yaml",
        }
    }
}

fn main() {
    let versions = lattice_helm_build::read_versions().expect("read versions.toml");
    let chart = versions
        .charts
        .get("cilium")
        .expect("versions.toml missing [charts.cilium]");
    let chart_path =
        lattice_helm_build::ensure_chart("cilium", chart).expect("ensure cilium chart");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));

    for mode in [LbMode::L2, LbMode::Bgp] {
        let args = build_args(mode);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let yaml =
            lattice_helm_build::render_chart(&chart_path, "cilium", "kube-system", &arg_refs)
                .expect("render cilium chart");
        std::fs::write(out_dir.join(mode.out_file()), yaml).expect("write cilium yaml");
    }

    std::fs::write(
        out_dir.join("kube_proxy_replacement.rs"),
        format!("pub const KUBE_PROXY_REPLACEMENT: bool = {KUBE_PROXY_REPLACEMENT};\n"),
    )
    .expect("write kube_proxy_replacement.rs");

    println!("cargo:rustc-env=CILIUM_VERSION={}", chart.version);
}

fn build_args(mode: LbMode) -> Vec<String> {
    // Args common to both variants. `String` (not `&str`) so the
    // mode-specific tail can interleave owned/borrowed values without
    // a second pass.
    let mut args: Vec<String> = vec![
        "--set",
        "hubble.enabled=true",
        "--set",
        "hubble.relay.enabled=true",
        "--set",
        "hubble.ui.enabled=true",
        "--set",
        "prometheus.enabled=false",
        "--set",
        "operator.prometheus.enabled=false",
        "--set",
        "cni.exclusive=false",
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
        "ipam.mode=kubernetes",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    match mode {
        LbMode::L2 => {
            // L2 announcements drive LB-IPAM (Cilium gARPs assigned
            // IPs on node interfaces). External advertisement of
            // cluster VIPs onto the wider LAN is the provider's job
            // (basis's proxy-ARP from the elected LAN-VIP owner;
            // bridge-mode for other providers).
            args.extend(
                [
                    "--set",
                    "l2announcements.enabled=true",
                    "--set",
                    "bgpControlPlane.enabled=false",
                ]
                .iter()
                .map(|s| s.to_string()),
            );
        }
        LbMode::Bgp => {
            // BGP control plane announces LB pool /32s into the cell
            // RR (basis-controller's embedded holod). Every node
            // peers with the RR; ECMP across announcers replaces the
            // L2-announce single-leader bottleneck. The
            // CiliumBGPClusterConfig + CiliumBGPAdvertisement CRDs
            // that name the RR + pool selectors are rendered per
            // cluster by basis-capi-provider, not bundled here.
            args.extend(
                [
                    "--set",
                    "l2announcements.enabled=false",
                    "--set",
                    "bgpControlPlane.enabled=true",
                ]
                .iter()
                .map(|s| s.to_string()),
            );
        }
    }

    if KUBE_PROXY_REPLACEMENT {
        args.extend(
            [
                "--set",
                "kubeProxyReplacement=true",
                // Istio ambient compatibility: scope Cilium's socket
                // LB to the host namespace only, so Pod-egress
                // traffic still falls through to ztunnel's iptables
                // redirection. Without this, socket LB rewrites the
                // destination inside the Pod's socket namespace
                // before iptables can match — bypassing the mesh
                // entirely.
                // See: https://docs.cilium.io/en/stable/network/servicemesh/istio/
                "--set",
                "socketLB.hostNamespaceOnly=true",
                "--set",
                "bpf.masquerade=false",
                "--set",
                "loadBalancer.acceleration=disabled",
                "--set-string",
                "k8sServiceHost=__LATTICE_API_SERVER_HOST__",
                "--set-string",
                "k8sServicePort=__LATTICE_API_SERVER_PORT__",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        args.extend(lb_mode_args(mode));
    } else {
        // Stock kube-proxy mode: explicitly disable Cilium's
        // replacement so chart defaults can't drift onto kPR. Source
        // IP preservation now depends on `externalTrafficPolicy:
        // Local` per Service rather than DSR.
        args.extend(
            ["--set", "kubeProxyReplacement=false"]
                .iter()
                .map(|s| s.to_string()),
        );
    }

    args
}

fn lb_mode_args(mode: LbMode) -> Vec<String> {
    match mode {
        LbMode::L2 => {
            // SNAT for the LB datapath. DSR is incompatible with
            // l2announcements: the announcer gARPs the LB IP but
            // Cilium only installs the IP on `lo` (so the kernel
            // accepts the packet for eBPF DNAT) under SNAT mode.
            // With DSR + L2 the packet hits the announcer, the
            // kernel has no local route, falls through to plain
            // forwarding, and bounces between the cluster gateway
            // and the LAN-VIP owner — observed as ICMP Redirect
            // Host storms when pinging an LB IP from outside the
            // cluster.
            ["--set", "loadBalancer.mode=snat"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
        LbMode::Bgp => {
            // SNAT, same as the L2 variant. The BGP win is in the
            // *advertisement* plane (route-based ECMP across every
            // node, no leader-elected L2-announce, no missing
            // IP-claim-on-lo bug), not the datapath. DSR was
            // tempting because it preserves source-IP at the LB,
            // but Cilium's DSR requires its own tunnel protocol
            // for `dsrDispatch=geneve` (would force
            // `routingMode=tunnel + tunnelProtocol=geneve`,
            // breaking `autoDirectNodeRoutes` and stacking
            // Cilium-Geneve inside basis-VXLAN). `dsrDispatch=opt`
            // works without tunneling but uses IPv4 options, which
            // some gear strips. SNAT avoids both gotchas; per-
            // Service source-IP preservation is recoverable with
            // `externalTrafficPolicy: Local`.
            ["--set", "loadBalancer.mode=snat"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
    }
}
