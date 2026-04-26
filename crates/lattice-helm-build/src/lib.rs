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
//!
//! All helpers return `Result<_, String>`. Build scripts `.expect()` at the
//! call site so failures surface with a clear cargo error message.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

pub type Result<T> = std::result::Result<T, String>;

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
pub fn workspace_root() -> Result<PathBuf> {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").map_err(|e| format!("CARGO_MANIFEST_DIR: {e}"))?;
    let parent = Path::new(&manifest_dir)
        .parent()
        .ok_or_else(|| format!("CARGO_MANIFEST_DIR has no parent: {manifest_dir}"))?
        .parent()
        .ok_or_else(|| format!("workspace root not found from {manifest_dir}"))?;
    Ok(parent.to_path_buf())
}

/// Directory charts and resources are downloaded into.
pub fn charts_dir() -> Result<PathBuf> {
    Ok(workspace_root()?.join("test-charts"))
}

/// Parse `workspace/versions.toml`. Emits `cargo:rerun-if-changed` for the
/// file so build scripts re-run when versions bump.
pub fn read_versions() -> Result<Versions> {
    let path = workspace_root()?.join("versions.toml");
    println!("cargo:rerun-if-changed={}", path.display());
    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    toml::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Absolute path to the chart tarball on disk, downloading if absent.
///
/// Handles both OCI (`oci://…`) and classic helm repos. Classic repos are
/// registered via `helm repo add` on first use.
pub fn ensure_chart(name: &str, chart: &Chart) -> Result<PathBuf> {
    let dir = charts_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;

    let filename = chart
        .filename
        .as_ref()
        .ok_or_else(|| format!("chart {name}: missing filename"))?
        .replace("{version}", &chart.version);
    let path = dir.join(&filename);
    if path.exists() {
        return Ok(path);
    }

    let chart_ref = chart
        .chart
        .as_ref()
        .ok_or_else(|| format!("chart {name}: missing chart ref"))?;

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
            .ok_or_else(|| format!("non-OCI chart {name}: missing repo"))?;
        let alias = chart_ref.split('/').next().unwrap_or(name);
        let repo_add = Command::new("helm")
            .args(["repo", "add", alias, repo, "--force-update"])
            .output()
            .map_err(|e| format!("helm repo add {alias}: {e}"))?;
        if !repo_add.status.success() {
            let stderr = String::from_utf8_lossy(&repo_add.stderr);
            return Err(format!("helm repo add {alias}: {stderr}"));
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
        .map_err(|e| format!("helm pull {chart_ref}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("helm pull {chart_ref} failed: {stderr}"));
    }
    if !path.exists() {
        return Err(format!(
            "helm pull succeeded but {} not found",
            path.display()
        ));
    }
    Ok(path)
}

/// Absolute path to a resource file on disk, downloading via `curl` if absent.
///
/// For `[resources.*]` entries (plain URL-sourced YAML such as the Gateway API
/// CRD bundle or the Volcano vGPU device plugin).
pub fn ensure_resource(name: &str, resource: &Resource) -> Result<PathBuf> {
    let dir = charts_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;

    let filename = resource
        .filename
        .as_ref()
        .ok_or_else(|| format!("resource {name}: missing filename"))?
        .replace("{version}", &resource.version);
    let path = dir.join(&filename);
    if path.exists() {
        return Ok(path);
    }

    let url = resource
        .url
        .as_ref()
        .ok_or_else(|| format!("resource {name}: missing url"))?
        .replace("{version}", &resource.version);

    eprintln!("cargo:warning=Downloading missing resource: {filename}");

    let output = Command::new("curl")
        .args(["-sL", "-o", &path.to_string_lossy(), &url])
        .output()
        .map_err(|e| format!("curl {url}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl {url} failed: {stderr}"));
    }
    Ok(path)
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
) -> Result<String> {
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
        .map_err(|e| format!("helm template {release}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("helm template {release} failed: {stderr}"));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("helm template {release} utf-8: {e}"))
}
