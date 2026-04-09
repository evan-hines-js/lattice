//! Helm subprocess wrapper — pull charts and render with `helm template`

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::PackageError;

/// Pull a chart from a repository and return the path to the chart directory.
///
/// Uses `helm pull --untar` into a temp directory. OCI and HTTPS repos are both supported.
pub fn pull_chart(
    repository: &str,
    name: &str,
    version: &str,
    cache_dir: &Path,
) -> Result<PathBuf, PackageError> {
    let chart_dir = cache_dir.join(format!("{}-{}", name, version));
    if chart_dir.exists() {
        return Ok(chart_dir);
    }

    std::fs::create_dir_all(cache_dir)
        .map_err(|e| PackageError::Helm(format!("failed to create cache dir: {}", e)))?;

    let chart_ref = if repository.starts_with("oci://") {
        format!("{}/{}", repository, name)
    } else {
        name.to_string()
    };

    let mut cmd = Command::new("helm");
    cmd.args(["pull", &chart_ref, "--version", version, "--untar", "--untardir"]);
    cmd.arg(cache_dir);

    if !repository.starts_with("oci://") {
        cmd.args(["--repo", repository]);
    }

    let output = cmd.output().map_err(|e| {
        PackageError::Helm(format!("failed to run helm pull: {}. Is helm installed?", e))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PackageError::Helm(format!(
            "helm pull {}/{} v{} failed: {}",
            repository, name, version, stderr
        )));
    }

    if !chart_dir.exists() {
        return Err(PackageError::Helm(format!(
            "helm pull succeeded but chart dir not found at {}",
            chart_dir.display()
        )));
    }

    Ok(chart_dir)
}

/// Render a chart with `helm template` and return the rendered YAML manifests.
///
/// `values_json` is the resolved values tree (all secrets substituted) serialized as JSON.
/// Helm accepts JSON as values via `--values` with a temp file.
pub fn template(
    release_name: &str,
    chart_path: &Path,
    namespace: &str,
    values_json: &str,
    skip_crds: bool,
) -> Result<String, PackageError> {
    // Write values to a temp file (helm reads from file, not stdin)
    let values_file = chart_path.join(".lattice-values.json");
    std::fs::write(&values_file, values_json).map_err(|e| {
        PackageError::Helm(format!("failed to write values file: {}", e))
    })?;

    let mut args = vec![
        "template",
        release_name,
        chart_path.to_str().unwrap_or("."),
        "--namespace",
        namespace,
        "--values",
        values_file.to_str().unwrap_or("."),
    ];

    if skip_crds {
        args.push("--skip-crds");
    }

    let output = Command::new("helm")
        .args(&args)
        .output()
        .map_err(|e| PackageError::Helm(format!("failed to run helm template: {}", e)))?;

    // Clean up temp values file
    let _ = std::fs::remove_file(&values_file);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PackageError::Helm(format!(
            "helm template {} failed: {}",
            release_name, stderr
        )));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| PackageError::Helm(format!("helm template produced invalid UTF-8: {}", e)))
}
