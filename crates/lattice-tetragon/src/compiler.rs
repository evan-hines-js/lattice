//! Tetragon runtime policy compilation
//!
//! Generates per-service TracingPolicyNamespaced resources from workload and runtime specs.
//!
//! Policy tiers:
//! - Tier 1: Binary execution whitelist (only declared + auto-detected entrypoints may run)
//! - Tier 2: Enforce security context at kernel level (rootfs, setuid, capabilities)

use std::collections::HashSet;

use lattice_common::crd::{
    ContainerSpec, Probe, RuntimeSpec, SecurityContext, SidecarSpec, WorkloadSpec,
};
use lattice_common::policy::tetragon::{
    KprobeArg, KprobeSpec, MatchArg, PodSelector, Selector, TracingPolicyNamespaced,
    TracingPolicySpec,
};

/// Compile TracingPolicyNamespaced resources for a workload.
///
/// Takes workload + runtime specs (not a specific CRD type) so it can be
/// called from LatticeService, LatticeJob, or LatticeModel controllers.
pub fn compile_tracing_policies(
    name: &str,
    namespace: &str,
    workload: &WorkloadSpec,
    runtime: &RuntimeSpec,
) -> Vec<TracingPolicyNamespaced> {
    let mut policies = Vec::new();

    // Tier 1: binary execution whitelist
    // "*" wildcard (explicit or inferred) disables all binary restrictions;
    // otherwise only declared + auto-detected entrypoints may execute.
    // Containers with no auto-detected entrypoints AND no allowedBinaries are
    // treated as allowedBinaries: ["*"] — Cedar must authorize this separately.
    // Explicit allowedBinaries: ["*"] always disables restrictions, even when
    // entrypoints exist (command, probes).
    let mut allowed_binaries = extract_allowed_binaries(workload, runtime);
    let entrypoints = extract_entrypoint_binaries(workload, runtime);
    if allowed_binaries.is_empty() && entrypoints.is_empty() {
        allowed_binaries.insert("*".to_string());
    }
    if !allowed_binaries.contains("*") {
        policies.push(compile_allow_binaries_policy(
            name,
            namespace,
            &allowed_binaries,
            &entrypoints,
        ));
    }

    // Tier 2: enforce declared security constraints at kernel level
    let security = aggregate_security_context(workload, runtime);

    if security.read_only_root_filesystem.unwrap_or(true) {
        policies.push(make_policy(
            "block-rootfs-write",
            name,
            namespace,
            KprobeSpec::with_args(
                "security_file_open",
                vec![KprobeArg {
                    index: 0,
                    type_: "file".to_string(),
                    label: Some("path".to_string()),
                }],
                vec![Selector::sigkill()],
            ),
        ));
    }

    if security.run_as_non_root.unwrap_or(true) {
        policies.push(make_policy(
            "block-setuid",
            name,
            namespace,
            KprobeSpec::simple(
                "security_task_fix_setuid",
                vec![Selector::sigkill()],
            ),
        ));
    }

    if security.capabilities.is_empty() {
        policies.push(make_policy(
            "block-capset",
            name,
            namespace,
            KprobeSpec::simple("security_capset", vec![Selector::sigkill()]),
        ));
    }

    policies
}

fn make_policy(
    prefix: &str,
    service_name: &str,
    namespace: &str,
    kprobe: KprobeSpec,
) -> TracingPolicyNamespaced {
    TracingPolicyNamespaced::new(
        format!("{prefix}-{service_name}"),
        namespace,
        TracingPolicySpec {
            pod_selector: Some(PodSelector::for_service(service_name)),
            kprobes: vec![kprobe],
        },
    )
}

/// Compile the allow-binaries policy: anything NOT in the whitelist gets SIGKILL'd.
///
/// The whitelist is the union of declared `allowedBinaries` plus entrypoint binaries
/// auto-detected from container/sidecar commands and exec probes.
fn compile_allow_binaries_policy(
    name: &str,
    namespace: &str,
    allowed_binaries: &HashSet<String>,
    entrypoints: &HashSet<String>,
) -> TracingPolicyNamespaced {
    let mut allowed = allowed_binaries.clone();
    allowed.extend(entrypoints.iter().cloned());

    let allowed_list: Vec<String> = allowed.into_iter().collect();

    let selectors = if allowed_list.is_empty() {
        vec![Selector::sigkill()]
    } else {
        let mut sel = Selector::sigkill();
        sel.match_args = vec![MatchArg {
            index: 0,
            operator: "NotEqual".to_string(),
            values: allowed_list,
        }];
        vec![sel]
    };

    make_policy(
        "allow-binaries",
        name,
        namespace,
        KprobeSpec::with_args(
            "security_bprm_check",
            vec![KprobeArg {
                index: 0,
                type_: "file".to_string(),
                label: Some("filename".to_string()),
            }],
            selectors,
        ),
    )
}

/// Collect `allowed_binaries` from all containers and sidecars (union)
fn extract_allowed_binaries(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> HashSet<String> {
    let mut binaries = HashSet::new();
    for container in workload.containers.values() {
        if let Some(sec) = &container.security {
            binaries.extend(sec.allowed_binaries.iter().cloned());
        }
    }
    for sidecar in runtime.sidecars.values() {
        if let Some(sec) = &sidecar.security {
            binaries.extend(sec.allowed_binaries.iter().cloned());
        }
    }
    binaries
}

/// Extract entrypoint binaries (command[0]) from containers, sidecars, and exec probes.
///
/// These are auto-allowed so that container entrypoints and health probes aren't
/// killed by the binary whitelist.
fn extract_entrypoint_binaries(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> HashSet<String> {
    let mut binaries = HashSet::new();
    for container in workload.containers.values() {
        collect_entrypoints_from_container(container, &mut binaries);
    }
    for sidecar in runtime.sidecars.values() {
        collect_entrypoints_from_sidecar(sidecar, &mut binaries);
    }
    binaries
}

fn collect_entrypoints_from_container(c: &ContainerSpec, binaries: &mut HashSet<String>) {
    collect_command_entrypoint(&c.command, binaries);
    collect_probe_entrypoint(&c.liveness_probe, binaries);
    collect_probe_entrypoint(&c.readiness_probe, binaries);
    collect_probe_entrypoint(&c.startup_probe, binaries);
}

fn collect_entrypoints_from_sidecar(s: &SidecarSpec, binaries: &mut HashSet<String>) {
    collect_command_entrypoint(&s.command, binaries);
    collect_probe_entrypoint(&s.liveness_probe, binaries);
    collect_probe_entrypoint(&s.readiness_probe, binaries);
    collect_probe_entrypoint(&s.startup_probe, binaries);
}

fn collect_command_entrypoint(cmd: &Option<Vec<String>>, binaries: &mut HashSet<String>) {
    if let Some(args) = cmd {
        if let Some(binary) = args.first() {
            binaries.insert(binary.clone());
        }
    }
}

fn collect_probe_entrypoint(probe: &Option<Probe>, binaries: &mut HashSet<String>) {
    if let Some(probe) = probe {
        if let Some(exec) = &probe.exec {
            if let Some(binary) = exec.command.first() {
                binaries.insert(binary.clone());
            }
        }
    }
}

/// Merge security contexts across all containers — most permissive wins
/// (if ANY container opts out of a restriction, we can't enforce it at kernel level)
fn aggregate_security_context(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> SecurityContext {
    let mut result = SecurityContext::default();

    for container in workload.containers.values() {
        if let Some(sec) = &container.security {
            merge_security(&mut result, sec);
        }
    }
    for sidecar in runtime.sidecars.values() {
        if let Some(sec) = &sidecar.security {
            merge_security(&mut result, sec);
        }
    }

    result
}

fn merge_security(agg: &mut SecurityContext, sec: &SecurityContext) {
    if sec.read_only_root_filesystem == Some(false) {
        agg.read_only_root_filesystem = Some(false);
    }
    if sec.run_as_non_root == Some(false) {
        agg.run_as_non_root = Some(false);
    }
    for cap in &sec.capabilities {
        if !agg.capabilities.contains(cap) {
            agg.capabilities.push(cap.clone());
        }
    }
    for bin in &sec.allowed_binaries {
        if !agg.allowed_binaries.contains(bin) {
            agg.allowed_binaries.push(bin.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        ContainerSpec, ExecProbe, Probe, RuntimeSpec, SecurityContext, WorkloadSpec,
    };

    use super::*;

    fn default_workload(security: Option<SecurityContext>) -> (WorkloadSpec, RuntimeSpec) {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                security,
                ..Default::default()
            },
        );
        (
            WorkloadSpec {
                containers,
                ..Default::default()
            },
            RuntimeSpec::default(),
        )
    }

    fn compile(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> Vec<TracingPolicyNamespaced> {
        compile_tracing_policies("my-app", "default", workload, runtime)
    }

    fn names(policies: &[TracingPolicyNamespaced]) -> Vec<&str> {
        policies.iter().map(|p| p.metadata.name.as_str()).collect()
    }

    fn allowed_values(policies: &[TracingPolicyNamespaced]) -> Vec<String> {
        let allow = policies
            .iter()
            .find(|p| p.metadata.name == "allow-binaries-my-app")
            .expect("allow-binaries policy should exist");
        let sel = &allow.spec.kprobes[0].selectors[0];
        if sel.match_args.is_empty() {
            vec![]
        } else {
            sel.match_args[0].values.clone()
        }
    }

    #[test]
    fn default_security_generates_tier2_policies() {
        let (w, r) = default_workload(None);
        let policies = compile(&w, &r);
        let n = names(&policies);
        assert!(n.contains(&"block-rootfs-write-my-app"));
        assert!(n.contains(&"block-setuid-my-app"));
        assert!(n.contains(&"block-capset-my-app"));
    }

    #[test]
    fn no_command_no_allowed_binaries_skips_binary_policy() {
        let (w, r) = default_workload(None);
        let policies = compile(&w, &r);
        let n = names(&policies);
        assert!(
            !n.contains(&"allow-binaries-my-app"),
            "No binary info → implicit wildcard, no policy"
        );
    }

    #[test]
    fn writable_rootfs_skips_file_open() {
        let (w, r) = default_workload(Some(SecurityContext {
            read_only_root_filesystem: Some(false),
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        assert!(!names(&policies).contains(&"block-rootfs-write-my-app"));
    }

    #[test]
    fn root_allowed_skips_setuid() {
        let (w, r) = default_workload(Some(SecurityContext {
            run_as_non_root: Some(false),
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        assert!(!names(&policies).contains(&"block-setuid-my-app"));
    }

    #[test]
    fn capabilities_requested_skips_capset() {
        let (w, r) = default_workload(Some(SecurityContext {
            capabilities: vec!["NET_ADMIN".to_string()],
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        assert!(!names(&policies).contains(&"block-capset-my-app"));
    }

    #[test]
    fn probe_entrypoint_auto_allowed() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                liveness_probe: Some(Probe {
                    http_get: None,
                    exec: Some(ExecProbe {
                        command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
                    }),
                }),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let r = RuntimeSpec::default();

        let values = allowed_values(&compile(&w, &r));
        assert!(
            values.contains(&"/bin/sh".to_string()),
            "/bin/sh should be auto-allowed as probe entrypoint"
        );
    }

    #[test]
    fn container_command_entrypoint_auto_allowed() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/usr/bin/python".to_string(), "app.py".to_string()]),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let r = RuntimeSpec::default();

        let values = allowed_values(&compile(&w, &r));
        assert!(values.contains(&"/usr/bin/python".to_string()));
        assert!(
            !values.contains(&"app.py".to_string()),
            "Only command[0] should be auto-allowed, not arguments"
        );
    }

    #[test]
    fn sidecar_command_entrypoint_auto_allowed() {
        let (w, _) = default_workload(None);
        let mut sidecars = BTreeMap::new();
        sidecars.insert(
            "log-shipper".to_string(),
            SidecarSpec {
                image: "fluent:latest".to_string(),
                command: Some(vec!["/bin/ash".to_string(), "-c".to_string(), "tail -f /dev/null".to_string()]),
                ..Default::default()
            },
        );
        let r = RuntimeSpec {
            sidecars,
            ..Default::default()
        };

        let values = allowed_values(&compile(&w, &r));
        assert!(values.contains(&"/bin/ash".to_string()));
    }

    #[test]
    fn declared_binaries_included_in_whitelist() {
        let (w, r) = default_workload(Some(SecurityContext {
            allowed_binaries: vec!["/usr/bin/curl".to_string(), "/usr/bin/convert".to_string()],
            ..Default::default()
        }));
        let values = allowed_values(&compile(&w, &r));
        assert!(values.contains(&"/usr/bin/curl".to_string()));
        assert!(values.contains(&"/usr/bin/convert".to_string()));
    }

    #[test]
    fn declared_binaries_plus_probe_entrypoint() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                security: Some(SecurityContext {
                    allowed_binaries: vec!["/usr/bin/curl".to_string()],
                    ..Default::default()
                }),
                liveness_probe: Some(Probe {
                    http_get: None,
                    exec: Some(ExecProbe {
                        command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
                    }),
                }),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let r = RuntimeSpec::default();

        let values = allowed_values(&compile(&w, &r));
        assert!(values.contains(&"/usr/bin/curl".to_string()));
        assert!(values.contains(&"/bin/sh".to_string()));
    }

    #[test]
    fn wildcard_disables_binary_policy() {
        let (w, r) = default_workload(Some(SecurityContext {
            allowed_binaries: vec!["*".to_string()],
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        let n = names(&policies);
        assert!(!n.contains(&"allow-binaries-my-app"));
    }

    #[test]
    fn allowed_binaries_uses_not_equal_operator() {
        let (w, r) = default_workload(Some(SecurityContext {
            allowed_binaries: vec!["/usr/bin/curl".to_string()],
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        let allow = policies
            .iter()
            .find(|p| p.metadata.name == "allow-binaries-my-app")
            .unwrap();
        assert_eq!(
            allow.spec.kprobes[0].selectors[0].match_args[0].operator,
            "NotEqual"
        );
    }

    #[test]
    fn allow_binaries_uses_bprm_check() {
        let (w, r) = default_workload(Some(SecurityContext {
            allowed_binaries: vec!["/usr/bin/curl".to_string()],
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        let allow = policies
            .iter()
            .find(|p| p.metadata.name == "allow-binaries-my-app")
            .unwrap();
        assert_eq!(allow.spec.kprobes[0].call, "security_bprm_check");
    }
}
