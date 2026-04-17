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

        // If a previous operation was interrupted (operator crash, pod eviction),
        // helm leaves the release in a pending-* state. Roll back to the last
        // successful revision to clear the lock, then retry the upgrade.
        if stderr.contains("another operation") && stderr.contains("in progress") {
            tracing::warn!(
                release = release_name,
                namespace = namespace,
                "Helm release stuck in pending state, rolling back stale lock"
            );
            rollback_stale_release(release_name, namespace)?;

            let retry_output = Command::new("helm")
                .args(&args)
                .output()
                .map_err(|e| {
                    PackageError::Helm(format!(
                        "failed to run helm upgrade --install (retry): {}",
                        e
                    ))
                })?;

            if !retry_output.status.success() {
                let retry_stderr = String::from_utf8_lossy(&retry_output.stderr);
                return Err(PackageError::Helm(format!(
                    "helm upgrade --install {} failed after rollback: {}",
                    release_name, retry_stderr
                )));
            }
            return Ok(());
        }

        return Err(PackageError::Helm(format!(
            "helm upgrade --install {} failed: {}",
            release_name, stderr
        )));
    }

    Ok(())
}

/// Roll back a helm release stuck in a pending-* state.
///
/// Checks the release history to determine the correct recovery action:
/// - If the only revision is pending (first install crashed), uninstalls to clear the lock.
/// - If there's a previous successful revision, rolls back to it.
/// - If the state is unrecognizable, returns an error rather than guessing.
fn rollback_stale_release(release_name: &str, namespace: &str) -> Result<(), PackageError> {
    // `helm history` shows all revisions and their statuses.
    // A stuck first install has exactly one revision with status "pending-install".
    let history_output = Command::new("helm")
        .args([
            "history",
            release_name,
            "--namespace",
            namespace,
            "--output",
            "json",
            "--max",
            "256",
        ])
        .output()
        .map_err(|e| PackageError::Helm(format!("failed to run helm history: {}", e)))?;

    if !history_output.status.success() {
        let stderr = String::from_utf8_lossy(&history_output.stderr);
        return Err(PackageError::Helm(format!(
            "helm history {} failed: {}",
            release_name, stderr
        )));
    }

    let history: serde_json::Value = serde_json::from_slice(&history_output.stdout)
        .map_err(|e| PackageError::Helm(format!("failed to parse helm history: {}", e)))?;

    let revisions = history.as_array().ok_or_else(|| {
        PackageError::Helm("helm history returned non-array".to_string())
    })?;

    // Check if every revision is in a pending/failed state (no successful revision exists)
    let has_deployed_revision = revisions.iter().any(|r| {
        r.get("status")
            .and_then(|s| s.as_str())
            .is_some_and(|s| s == "deployed" || s == "superseded")
    });

    if has_deployed_revision {
        // There's a good revision to roll back to
        tracing::info!(
            release = release_name,
            "Found previous deployed revision, rolling back"
        );
        let output = Command::new("helm")
            .args([
                "rollback",
                release_name,
                "--namespace",
                namespace,
                "--wait",
            ])
            .output()
            .map_err(|e| PackageError::Helm(format!("failed to run helm rollback: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PackageError::Helm(format!(
                "helm rollback {} failed: {}",
                release_name, stderr
            )));
        }
        tracing::info!(release = release_name, "Rolled back stale helm release");
        Ok(())
    } else {
        // No successful revision — stuck on first install. Safe to uninstall.
        let statuses: Vec<&str> = revisions
            .iter()
            .filter_map(|r| r.get("status").and_then(|s| s.as_str()))
            .collect();
        tracing::warn!(
            release = release_name,
            ?statuses,
            "No deployed revision found, uninstalling to clear stale lock"
        );
        uninstall(release_name, namespace)
    }
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
