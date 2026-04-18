//! Workload → Tetragon TracingPolicy compiler.
//!
//! Generates per-service `TracingPolicyNamespaced` resources from workload and
//! runtime specs. Called by every workload controller (LatticeService,
//! LatticeJob, LatticeModel) to enforce binary-execution whitelisting at the
//! kernel via eBPF kprobes on LSM hooks.
//!
//! Independent of the Tetragon dependency install (see `lattice-tetragon`).
//! This crate only produces policy manifests; the `lattice-tetragon` install
//! controller is what puts Tetragon on the cluster in the first place.

mod compiler;

pub use compiler::compile_tracing_policies;
