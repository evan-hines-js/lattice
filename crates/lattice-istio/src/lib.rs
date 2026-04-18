//! Istio ambient dependency install.
//!
//! Owns the four Istio helm charts (base, cni, istiod, ztunnel), per-cluster
//! template substitution, trust-domain derivation from `lattice-ca`, the
//! `cacerts` Secret for intermediate-CA signing, the east-west Gateway, and
//! the five mesh-wide security policies (STRICT mTLS, default-deny,
//! waypoint-default-deny, operator-allow, eastwest-gateway-allow).

pub mod install;
