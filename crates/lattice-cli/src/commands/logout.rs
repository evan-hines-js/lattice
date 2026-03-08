//! Logout command — clear saved credentials and proxy kubeconfig.
//!
//! Removes `~/.lattice/kubeconfig` and `~/.lattice/config.json` so subsequent
//! commands fall back to the default kubeconfig resolution chain.

use clap::Args;
use tracing::info;

use crate::Result;

/// Clear saved credentials and proxy kubeconfig
#[derive(Args, Debug)]
pub struct LogoutArgs {}

/// Remove a config file, returning whether it existed.
/// Ignores NotFound errors; propagates all others.
fn remove_config_file(path: &std::path::Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            info!("Removed {}", path.display());
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(crate::Error::command_failed(format!(
            "failed to remove {}: {}",
            path.display(),
            e
        ))),
    }
}

pub async fn run(_args: LogoutArgs) -> Result<()> {
    let mut removed = false;

    if let Ok(path) = crate::config::kubeconfig_path() {
        removed |= remove_config_file(&path)?;
    }

    if let Ok(path) = crate::config::config_path() {
        removed |= remove_config_file(&path)?;
    }

    if removed {
        println!("Logged out. Saved credentials have been removed.");
    } else {
        println!("Already logged out (no saved credentials found).");
    }

    Ok(())
}
