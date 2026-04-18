//! Shared build-script helpers for rendering helm charts into `$OUT_DIR`.
//!
//! Consumed as a `[build-dependencies]` crate by every per-dependency install
//! crate's `build.rs` (`lattice-tetragon`, future `lattice-eso`, `lattice-cilium`,
//! etc.) so they don't each copy the same `helm pull` / `helm template` /
//! `versions.toml` parsing logic.
//!
//! Three primitives:
//! - [`read_versions`] — parse `workspace/versions.toml` once per build.
//! - [`ensure_chart`] / [`ensure_resource`] — download the artifact if missing
//!   (OCI + classic helm repos + plain URL-sourced YAML).
//! - [`render_chart`] — run `helm template` and return the rendered YAML.
//!
//! Each consumer composes these in a handful of lines. Control-flow logic
//! (what values to pass, how to post-process, when to bail out) stays in the
//! consumer — this crate is plumbing only.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

/// Parsed `versions.toml` at the workspace root.
#[derive(Debug, Deserialize)]
pub struct Versions {
    #[serde(default)]
    pub charts: HashMap<String, Chart>,
    #[serde(default)]
    pub resources: HashMap<String, Resource>,
}

/// One `[charts.*]` entry.
#[derive(Debug, Deserialize)]
pub struct Chart {
    pub version: String,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub chart: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
}

/// One `[resources.*]` entry (plain URL-sourced file, not a helm chart).
#[derive(Debug, Deserialize)]
pub struct Resource {
    pub version: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
}

/// Workspace root computed from `$CARGO_MANIFEST_DIR` (two `.parent()` hops
/// from `crates/<crate>/`).
///
/// Consumers use this to locate `versions.toml` and the shared chart cache.
pub fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    Path::new(&manifest_dir)
        .parent()
        .expect("CARGO_MANIFEST_DIR parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Directory charts and resources are downloaded into.
///
/// Shared across every consumer's build so a chart downloaded by one crate
/// is reused by the next.
pub fn charts_dir() -> PathBuf {
    workspace_root().join("test-charts")
}

/// Parse `workspace/versions.toml`. Emits `cargo:rerun-if-changed` for the
/// file so build scripts re-run when versions bump.
pub fn read_versions() -> Versions {
    let path = workspace_root().join("versions.toml");
    println!("cargo:rerun-if-changed={}", path.display());
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    toml::from_str(&raw).expect("versions.toml parse")
}

/// Absolute path to the chart tarball on disk, downloading if absent.
///
/// Handles both OCI (`oci://…`) and classic helm repos. Classic repos are
/// registered via `helm repo add` on first use.
pub fn ensure_chart(name: &str, chart: &Chart) -> PathBuf {
    let dir = charts_dir();
    std::fs::create_dir_all(&dir).expect("create charts dir");

    let filename = chart
        .filename
        .as_ref()
        .unwrap_or_else(|| panic!("chart {name}: missing filename"))
        .replace("{version}", &chart.version);
    let path = dir.join(&filename);
    if path.exists() {
        return path;
    }

    let chart_ref = chart
        .chart
        .as_ref()
        .unwrap_or_else(|| panic!("chart {name}: missing chart ref"));

    eprintln!("cargo:warning=Downloading missing chart: {filename}");

    let mut cmd = Command::new("helm");
    if chart_ref.starts_with("oci://") {
        cmd.args([
            "pull",
            chart_ref,
            "--version",
            &format!("v{}", chart.version),
            "--destination",
            &dir.to_string_lossy(),
        ]);
    } else {
        let repo = chart
            .repo
            .as_ref()
            .unwrap_or_else(|| panic!("non-OCI chart {name}: missing repo"));
        let alias = chart_ref.split('/').next().unwrap_or(name);
        let repo_add = Command::new("helm")
            .args(["repo", "add", alias, repo, "--force-update"])
            .output()
            .expect("helm repo add");
        if !repo_add.status.success() {
            let stderr = String::from_utf8_lossy(&repo_add.stderr);
            panic!("helm repo add {alias}: {stderr}");
        }
        cmd.args([
            "pull",
            chart_ref,
            "--version",
            &chart.version,
            "--destination",
            &dir.to_string_lossy(),
        ]);
    }

    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("helm pull {chart_ref}: {e}"));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("helm pull {chart_ref} failed: {stderr}");
    }
    assert!(
        path.exists(),
        "helm pull succeeded but {} not found",
        path.display()
    );
    path
}

/// Absolute path to a resource file on disk, downloading via `curl` if absent.
///
/// For `[resources.*]` entries (plain URL-sourced YAML such as the Gateway API
/// CRD bundle or the Volcano vGPU device plugin).
pub fn ensure_resource(name: &str, resource: &Resource) -> PathBuf {
    let dir = charts_dir();
    std::fs::create_dir_all(&dir).expect("create charts dir");

    let filename = resource
        .filename
        .as_ref()
        .unwrap_or_else(|| panic!("resource {name}: missing filename"))
        .replace("{version}", &resource.version);
    let path = dir.join(&filename);
    if path.exists() {
        return path;
    }

    let url = resource
        .url
        .as_ref()
        .unwrap_or_else(|| panic!("resource {name}: missing url"))
        .replace("{version}", &resource.version);

    eprintln!("cargo:warning=Downloading missing resource: {filename}");

    let output = Command::new("curl")
        .args(["-sL", "-o", &path.to_string_lossy(), &url])
        .output()
        .unwrap_or_else(|e| panic!("curl {url}: {e}"));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("curl {url} failed: {stderr}");
    }
    path
}

/// Run `helm template` and return the rendered YAML.
///
/// `--include-crds` is always passed so CRDs are rendered inline (the default
/// `--skip-crds` behavior would force consumers to install CRDs separately).
pub fn render_chart(
    chart_path: &Path,
    release: &str,
    namespace: &str,
    extra_args: &[&str],
) -> String {
    let output = Command::new("helm")
        .args([
            "template",
            release,
            &chart_path.to_string_lossy(),
            "--namespace",
            namespace,
            "--include-crds",
        ])
        .args(extra_args)
        .output()
        .unwrap_or_else(|e| panic!("helm template {release}: {e}"));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("helm template {release} failed: {stderr}");
    }
    String::from_utf8(output.stdout).expect("helm template utf-8")
}
