//! Deterministic hashing utilities.

/// Compute a deterministic hash of the input string, returning a 16-char hex digest.
///
/// Uses truncated SHA-256 for stability across Rust toolchain versions.
/// `DefaultHasher` is NOT guaranteed stable across Rust releases, so this
/// function should be used whenever the hash is persisted (e.g., K8s annotations).
pub fn deterministic_hash(input: &str) -> String {
    use aws_lc_rs::digest;
    let hash = digest::digest(&digest::SHA256, input.as_bytes());
    // Take first 8 bytes (16 hex chars) for a compact annotation value
    hash.as_ref()[..8]
        .iter()
        .fold(String::with_capacity(16), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
            s
        })
}
