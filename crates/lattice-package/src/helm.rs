//! Helm subprocess wrapper — install, upgrade, and uninstall releases

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::PackageError;

/// Pull a chart from a repository and return the path to the chart directory.
///
/// Uses `helm pull --untar` into a cache directory. OCI and HTTPS repos supported.
/// Validates the cache by checking for `Chart.yaml`. Cleans up partial pulls.
pub fn pull_chart(
    repository: &str,
    name: &str,
    version: &str,
    cache_dir: &Path,
) -> Result<PathBuf, PackageError> {
    // helm pull --untar extracts to {untardir}/{chart_name}/
    let chart_dir = cache_dir.join(name);

    // Valid cache: Chart.yaml exists
    if chart_dir.join("Chart.yaml").exists() {
        return Ok(chart_dir);
    }

    // Partial/corrupt cache — remove before re-pulling
    if chart_dir.exists() {
        let _ = std::fs::remove_dir_all(&chart_dir);
    }

    std::fs::create_dir_all(cache_dir)
        .map_err(|e| PackageError::Helm(format!("failed to create cache dir: {}", e)))?;

    let chart_ref = if repository.starts_with("oci://") {
        format!("{}/{}", repository, name)
    } else {
        name.to_string()
    };

    let mut cmd = Command::new("helm");
    cmd.args([
        "pull",
        &chart_ref,
        "--version",
        version,
        "--untar",
        "--untardir",
    ]);
    cmd.arg(cache_dir);

    if !repository.starts_with("oci://") {
        cmd.args(["--repo", repository]);
    }

    let output = cmd.output().map_err(|e| {
        PackageError::Helm(format!(
            "failed to run helm pull: {}. Is helm installed?",
            e
        ))
    })?;

    if !output.status.success() {
        // Clean up any partial extraction
        let _ = std::fs::remove_dir_all(&chart_dir);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PackageError::Helm(format!(
            "helm pull {}/{} v{} failed: {}",
            repository, name, version, stderr
        )));
    }

    if !chart_dir.join("Chart.yaml").exists() {
        let _ = std::fs::remove_dir_all(&chart_dir);
        return Err(PackageError::Helm(format!(
            "helm pull succeeded but Chart.yaml not found at {}",
            chart_dir.display()
        )));
    }

    Ok(chart_dir)
}

/// Install or upgrade a Helm release.
///
/// Uses `helm upgrade --install` which handles both initial install and
/// subsequent upgrades idempotently.
pub fn install_or_upgrade(
    release_name: &str,
    chart_path: &Path,
    namespace: &str,
    values_json: &str,
    create_namespace: bool,
    skip_crds: bool,
    timeout: Option<&str>,
) -> Result<(), PackageError> {
    // Write values to a temp file
    let values_file = chart_path.join(".lattice-values.json");
    std::fs::write(&values_file, values_json)
        .map_err(|e| PackageError::Helm(format!("failed to write values file: {}", e)))?;

    let mut args = vec![
        "upgrade",
        "--install",
        release_name,
        chart_path.to_str().unwrap_or("."),
        "--namespace",
        namespace,
        "--values",
        values_file.to_str().unwrap_or("."),
        "--wait",
    ];

    if create_namespace {
        args.push("--create-namespace");
    }
    if skip_crds {
        args.push("--skip-crds");
    }

    let timeout_str;
    if let Some(t) = timeout {
        timeout_str = t.to_string();
        args.push("--timeout");
        args.push(&timeout_str);
    }

    let output = Command::new("helm")
        .args(&args)
        .output()
        .map_err(|e| PackageError::Helm(format!("failed to run helm upgrade --install: {}", e)))?;

    // Clean up temp values file
    let _ = std::fs::remove_file(&values_file);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PackageError::Helm(format!(
            "helm upgrade --install {} failed: {}",
            release_name, stderr
        )));
    }

    Ok(())
}

/// Uninstall a Helm release. Returns Ok even if the release doesn't exist.
pub fn uninstall(release_name: &str, namespace: &str) -> Result<(), PackageError> {
    let output = Command::new("helm")
        .args([
            "uninstall",
            release_name,
            "--namespace",
            namespace,
            "--wait",
        ])
        .output()
        .map_err(|e| PackageError::Helm(format!("failed to run helm uninstall: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "not found" is fine — release was already deleted or never installed
        if stderr.contains("not found") {
            return Ok(());
        }
        return Err(PackageError::Helm(format!(
            "helm uninstall {} failed: {}",
            release_name, stderr
        )));
    }

    Ok(())
}
