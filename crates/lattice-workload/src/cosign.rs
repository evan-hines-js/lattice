//! Image signature verification via the `cosign` CLI.
//!
//! sigstore-rs pulls native-tls/openssl, which conflicts with the FIPS
//! aws-lc-rs requirement. The cosign binary is shipped in the operator
//! image and invoked as a subprocess.

use std::io::Write;
use std::process::Stdio;

use tempfile::NamedTempFile;
use tokio::process::Command;
use tracing::{debug, info};

#[derive(Debug)]
pub enum VerifyResult {
    Verified,
    NotSigned(String),
    Error(String),
}

pub async fn verify_image(image: &str, key_pem: &[u8], insecure: bool) -> VerifyResult {
    let mut keyfile = match NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => return VerifyResult::Error(format!("failed to create temp keyfile: {e}")),
    };
    if let Err(e) = keyfile.write_all(key_pem) {
        return VerifyResult::Error(format!("failed to write cosign key: {e}"));
    }
    if let Err(e) = keyfile.flush() {
        return VerifyResult::Error(format!("failed to flush cosign key: {e}"));
    }

    let mut cmd = Command::new("cosign");
    cmd.arg("verify")
        .arg("--key")
        .arg(keyfile.path())
        .arg("--insecure-ignore-tlog=true")
        .arg("--insecure-ignore-sct=true")
        .arg("--output")
        .arg("json");
    if insecure {
        cmd.arg("--allow-insecure-registry");
    }
    cmd.arg(image);
    cmd.env("COSIGN_EXPERIMENTAL", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => return VerifyResult::Error(format!("failed to spawn cosign: {e}")),
    };

    if output.status.success() {
        info!(image = image, "signature verification succeeded");
        return VerifyResult::Verified;
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let lower = stderr.to_lowercase();
    let unsigned = lower.contains("no matching signatures")
        || lower.contains("no signatures found")
        || lower.contains("manifest_unknown")
        || lower.contains("not found")
        || lower.contains("signature not found");

    if unsigned {
        debug!(image = image, error = %stderr, "no valid signature");
        VerifyResult::NotSigned(format!("no valid signature for {image}: {stderr}"))
    } else {
        VerifyResult::Error(format!("cosign verify failed for {image}: {stderr}"))
    }
}
