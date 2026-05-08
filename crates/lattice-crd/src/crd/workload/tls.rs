//! TLS configuration shared across exposure mechanisms (Gateway-API ingress
//! routes, LoadBalancer / NodePort Services). Mode is inferred from which
//! field is set:
//!
//! | Fields present  | Behavior                                                |
//! |-----------------|---------------------------------------------------------|
//! | `issuerRef`     | Auto — cert-manager provisions via the named issuer     |
//! | `secretName`    | Manual — caller supplies the TLS secret                 |
//! | empty `tls: {}` | Auto — uses platform default (`PLATFORM_CA_ISSUER_NAME`)|
//! | no `tls` field  | No TLS                                                  |
//! | both fields     | Validation error                                        |

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Name of the built-in `CertIssuer` shipped by every Lattice cluster.
///
/// Wraps the operator-managed `lattice-ca` Secret as a `type: ca` issuer,
/// installed via [`crate::crd::CaIssuerSpec::SecretRef`]. This is the
/// trust anchor every `service.tls: {}` defaults to — services don't need
/// to declare an `issuerRef` for the common case.
///
/// The published cert-manager `ClusterIssuer` is named identically. Achieved
/// by reserving [`PLATFORM_CA_ISSUER_KEY`] in `LatticeClusterSpec.issuers`
/// so that the operator's reconcile path always emits this issuer with no
/// `lattice-` prefix-prefix collision.
pub const PLATFORM_CA_ISSUER_NAME: &str = "lattice-ca";

/// Reserved registry key for the platform CertIssuer in
/// `LatticeClusterSpec.issuers`. The published cert-manager ClusterIssuer
/// name is `lattice-{key}`, so `key = "ca"` yields `lattice-ca` =
/// [`PLATFORM_CA_ISSUER_NAME`]. User-defined entries cannot use this key
/// (rejected by `LatticeClusterSpec::validate`).
pub const PLATFORM_CA_ISSUER_KEY: &str = "ca";

/// TLS configuration for any TLS-terminating endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TlsSpec {
    /// Secret name containing TLS certificate (manual mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,

    /// cert-manager issuer reference (auto mode). When omitted on a TLS
    /// block that isn't using `secretName`, [`Self::effective_issuer_ref`]
    /// falls back to [`PLATFORM_CA_ISSUER_NAME`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<CertIssuerRef>,
}

impl TlsSpec {
    /// True when the caller has supplied a pre-existing TLS Secret.
    pub fn is_manual(&self) -> bool {
        self.secret_name.is_some()
    }

    /// Resolve the issuer cert-manager should sign with for this TLS spec,
    /// applying the platform default when no explicit `issuerRef` is set.
    /// Returns `None` for manual mode (`secretName` only) — there's no
    /// Certificate to emit because the caller provides the Secret directly.
    pub fn effective_issuer_ref(&self) -> Option<CertIssuerRef> {
        if self.is_manual() {
            return None;
        }
        Some(self.issuer_ref.clone().unwrap_or_else(|| CertIssuerRef {
            name: PLATFORM_CA_ISSUER_NAME.to_string(),
            kind: None,
        }))
    }

    /// Resolve the K8s Secret name a TLS-terminating sidecar should mount.
    /// Manual mode (`secretName`) wins; otherwise the caller's auto-mode
    /// default (e.g. `{service}-tls` for Services, `{service}-{route}-tls`
    /// for routes).
    pub fn resolved_secret_name(&self, auto_default: &str) -> String {
        self.secret_name
            .clone()
            .unwrap_or_else(|| auto_default.to_string())
    }

    /// Validate that auto and manual modes are not both requested.
    pub fn validate(&self, context: &str) -> Result<(), String> {
        if self.issuer_ref.is_some() && self.secret_name.is_some() {
            return Err(format!(
                "{context}: cannot specify both issuerRef and secretName in tls"
            ));
        }
        Ok(())
    }
}

/// Reference to a cert-manager issuer.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertIssuerRef {
    /// Name of the issuer.
    pub name: String,

    /// Issuer kind (defaults to `ClusterIssuer`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl CertIssuerRef {
    /// Issuer kind, defaulting to `ClusterIssuer` per cert-manager conventions.
    pub fn kind_or_default(&self) -> &str {
        self.kind.as_deref().unwrap_or("ClusterIssuer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_and_manual_are_mutually_exclusive() {
        let tls = TlsSpec {
            secret_name: Some("my-tls".to_string()),
            issuer_ref: Some(CertIssuerRef {
                name: "ca".to_string(),
                kind: None,
            }),
        };
        assert!(tls.validate("test").is_err());
    }

    #[test]
    fn explicit_issuer_ref_is_used_verbatim() {
        let tls = TlsSpec {
            secret_name: None,
            issuer_ref: Some(CertIssuerRef {
                name: "ca".to_string(),
                kind: None,
            }),
        };
        assert!(tls.validate("test").is_ok());
        let issuer = tls.effective_issuer_ref().expect("auto mode");
        assert_eq!(issuer.name, "ca");
        assert!(!tls.is_manual());
    }

    #[test]
    fn manual_secret_name_short_circuits_issuer_resolution() {
        let tls = TlsSpec {
            secret_name: Some("my-tls".to_string()),
            issuer_ref: None,
        };
        assert!(tls.validate("test").is_ok());
        assert!(tls.is_manual());
        assert!(
            tls.effective_issuer_ref().is_none(),
            "manual mode owns the Secret; no Certificate to emit"
        );
    }

    #[test]
    fn empty_block_falls_back_to_platform_default() {
        let tls = TlsSpec::default();
        assert!(tls.validate("test").is_ok());
        let issuer = tls
            .effective_issuer_ref()
            .expect("default applies to empty TLS blocks");
        assert_eq!(issuer.name, PLATFORM_CA_ISSUER_NAME);
        assert_eq!(issuer.kind_or_default(), "ClusterIssuer");
    }

    #[test]
    fn cert_issuer_kind_defaults_to_cluster_issuer() {
        let r = CertIssuerRef {
            name: "ca".to_string(),
            kind: None,
        };
        assert_eq!(r.kind_or_default(), "ClusterIssuer");

        let r = CertIssuerRef {
            name: "ca".to_string(),
            kind: Some("Issuer".to_string()),
        };
        assert_eq!(r.kind_or_default(), "Issuer");
    }
}
