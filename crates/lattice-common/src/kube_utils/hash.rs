//! Deterministic hashing utilities.
//!
//! Re-exports from `lattice_core` — the canonical implementations live there.

pub use lattice_core::{deterministic_hash, sha256};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_produces_32_byte_output() {
        let hash = sha256(b"hello world");
        assert_eq!(hash.len(), 32, "SHA-256 must produce exactly 32 bytes");
    }

    #[test]
    fn sha256_is_deterministic() {
        let hash1 = sha256(b"deterministic input");
        let hash2 = sha256(b"deterministic input");
        assert_eq!(hash1, hash2, "Same input must produce identical hashes");
    }

    #[test]
    fn sha256_different_inputs_produce_different_hashes() {
        let hash_a = sha256(b"input a");
        let hash_b = sha256(b"input b");
        assert_ne!(
            hash_a, hash_b,
            "Different inputs should produce different hashes"
        );
    }

    #[test]
    fn sha256_empty_input_produces_valid_hash() {
        let hash = sha256(b"");
        assert_eq!(hash.len(), 32, "Empty input must still produce 32 bytes");
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let actual_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            actual_hex, expected_hex,
            "Empty-string SHA-256 must match the known digest"
        );
    }

    #[test]
    fn deterministic_hash_produces_16_char_hex() {
        let hash = deterministic_hash("test input");
        assert_eq!(hash.len(), 16, "Truncated hash must be 16 hex characters");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "All characters must be hex digits"
        );
    }

    #[test]
    fn deterministic_hash_is_stable() {
        let hash1 = deterministic_hash("stable");
        let hash2 = deterministic_hash("stable");
        assert_eq!(
            hash1, hash2,
            "Same input must produce identical truncated hashes"
        );
    }
}
