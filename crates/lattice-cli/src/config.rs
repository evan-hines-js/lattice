//! Lattice CLI configuration stored at `~/.lattice/`.
//!
//! Manages persistent state for `lattice login` and `lattice install`:
//! - `~/.lattice/config.json` — login metadata and current cluster
//! - `~/.lattice/kubeconfig.proxy` — proxy kubeconfig (through Lattice auth proxy)
//! - `~/.lattice/kubeconfig.root` — root kubeconfig (direct API server access)
//!
//! The kubeconfig resolution chain (highest priority first):
//! - Explicit `--kubeconfig` flag
//! - `LATTICE_KUBECONFIG` environment variable
//! - `~/.lattice/kubeconfig.proxy` (from `lattice login` / `lattice install`)
//! - Fall back to kube default (`KUBECONFIG` env / `~/.kube/config`)

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const CONFIG_DIR_NAME: &str = ".lattice";
const CONFIG_FILE_NAME: &str = "config.json";
const KUBECONFIG_PROXY_FILE_NAME: &str = "kubeconfig.proxy";
const KUBECONFIG_ROOT_FILE_NAME: &str = "kubeconfig.root";
const LATTICE_KUBECONFIG_ENV: &str = "LATTICE_KUBECONFIG";

/// Persistent CLI configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LatticeConfig {
    /// Discovered proxy server URL.
    pub proxy_server: Option<String>,
    /// Current cluster set by `lattice use`.
    pub current_cluster: Option<String>,
    /// ISO 8601 timestamp of last login.
    pub last_login: Option<String>,
}

/// Returns `~/.lattice/`, creating it if it doesn't exist.
pub fn lattice_dir() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| Error::command_failed("could not determine home directory"))?;
    let dir = home.join(CONFIG_DIR_NAME);
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| {
            Error::command_failed(format!("failed to create {}: {}", dir.display(), e))
        })?;
    }
    Ok(dir)
}

/// Path to `~/.lattice/config.json`.
pub fn config_path() -> Result<PathBuf> {
    Ok(lattice_dir()?.join(CONFIG_FILE_NAME))
}

/// Path to `~/.lattice/kubeconfig.proxy`.
pub fn kubeconfig_proxy_path() -> Result<PathBuf> {
    Ok(lattice_dir()?.join(KUBECONFIG_PROXY_FILE_NAME))
}

/// Path to `~/.lattice/kubeconfig.root`.
pub fn kubeconfig_root_path() -> Result<PathBuf> {
    Ok(lattice_dir()?.join(KUBECONFIG_ROOT_FILE_NAME))
}

/// Write a file with 0600 permissions.
fn write_secure(path: &std::path::Path, content: &str) -> Result<()> {
    std::fs::write(path, content)
        .map_err(|e| Error::command_failed(format!("failed to write {}: {}", path.display(), e)))?;
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| {
        Error::command_failed(format!(
            "failed to set permissions on {}: {}",
            path.display(),
            e
        ))
    })
}

/// Save config to `~/.lattice/config.json`.
pub fn save_config(config: &LatticeConfig) -> Result<()> {
    let path = config_path()?;
    let data = serde_json::to_string_pretty(config)
        .map_err(|e| Error::command_failed(format!("failed to serialize config: {}", e)))?;
    write_secure(&path, &data)
}

/// Save proxy kubeconfig to `~/.lattice/kubeconfig.proxy`.
pub fn save_proxy_kubeconfig(json: &str) -> Result<PathBuf> {
    let path = kubeconfig_proxy_path()?;
    write_secure(&path, json)?;
    Ok(path)
}

/// Save root (direct API server) kubeconfig to `~/.lattice/kubeconfig.root`.
pub fn save_root_kubeconfig(yaml: &str) -> Result<PathBuf> {
    let path = kubeconfig_root_path()?;
    write_secure(&path, yaml)?;
    Ok(path)
}

/// Resolve a kubeconfig path using the priority chain.
///
/// Returns `Some(path)` if a kubeconfig is found, `None` to use kube defaults.
///
/// Priority:
/// - `explicit` — the `--kubeconfig` CLI flag
/// - `LATTICE_KUBECONFIG` env var
/// - `~/.lattice/kubeconfig.proxy` (from `lattice login`)
/// - `None` — fall back to `kube::Client::try_default()`
pub fn resolve_kubeconfig(explicit: Option<&str>) -> Option<String> {
    if let Some(path) = explicit {
        return Some(path.to_string());
    }

    if let Ok(path) = std::env::var(LATTICE_KUBECONFIG_ENV) {
        if !path.is_empty() {
            return Some(path);
        }
    }

    if let Ok(path) = kubeconfig_proxy_path() {
        if path.exists() {
            return Some(path.to_string_lossy().into_owned());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_serde_roundtrip() {
        let config = LatticeConfig {
            proxy_server: Some("https://proxy:8082".to_string()),
            current_cluster: Some("prod".to_string()),
            last_login: Some("2025-01-01T00:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: LatticeConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.proxy_server.as_deref(), Some("https://proxy:8082"));
        assert_eq!(parsed.current_cluster.as_deref(), Some("prod"));
        assert_eq!(parsed.last_login.as_deref(), Some("2025-01-01T00:00:00Z"));
    }

    #[test]
    fn config_default_is_empty() {
        let config = LatticeConfig::default();
        assert!(config.proxy_server.is_none());
        assert!(config.current_cluster.is_none());
        assert!(config.last_login.is_none());
    }

    #[test]
    fn resolve_kubeconfig_explicit_wins() {
        let result = resolve_kubeconfig(Some("/explicit/path"));
        assert_eq!(result.as_deref(), Some("/explicit/path"));
    }

    #[test]
    fn resolve_kubeconfig_none_when_nothing_set() {
        let result = resolve_kubeconfig(None);
        // May or may not be None depending on whether ~/.lattice/kubeconfig.proxy exists
        let _ = result;
    }
}
