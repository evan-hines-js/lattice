//! Status change detection for CRD controllers.
//!
//! Prevents redundant status patches that trigger self-reconcile storms.
//! Each merge patch generates a watch event (especially because `Condition::new()`
//! stamps a fresh `lastTransitionTime`), so controllers must skip no-op updates.

// `InstallStatus` is intentionally not wired into this generic helper: it
// has its own multi-field steady-state check (manifest hash, observed
// version, requires condition) inside `crate::install::is_steady_state`.
use kube::{Client, Resource, ResourceExt};
use tracing::debug;

use crate::error::ReconcileError;
use lattice_crd::crd::{
    BackupStorePhase, BackupStoreStatus, CertIssuerPhase, CertIssuerStatus, ClusterBackupPhase,
    DNSProviderPhase, DNSProviderStatus, ImageProviderPhase, ImageProviderStatus,
    InfraProviderPhase, InfraProviderStatus, JobPhase, LatticeClusterBackupStatus,
    LatticeJobStatus, LatticeMeshMemberStatus, LatticeModelStatus, LatticeRestoreStatus,
    LatticeServiceStatus, MeshMemberPhase, ModelServingPhase, RestorePhase, SecretProviderPhase,
    SecretProviderStatus, ServicePhase,
};

/// Trait for CRD status structs that carry phase, message, and observed generation.
///
/// Implement this for each CRD status type to enable generic `is_status_unchanged` checks.
pub trait StatusFields {
    /// The phase enum type for this CRD.
    type Phase: PartialEq;

    /// Current phase of the resource.
    fn phase(&self) -> &Self::Phase;

    /// Human-readable status message.
    fn message(&self) -> Option<&str>;

    /// Generation of the spec that was last reconciled.
    fn observed_generation(&self) -> Option<i64>;
}

/// Build a fresh status value from `(phase, message, observed_generation)`.
///
/// Implement for status types that have NO additional required fields
/// beyond the [`StatusFields`] trio — most CRD statuses qualify. Status
/// types with extra fields (e.g. `InfraProviderStatus::last_validated`)
/// supply their own implementation that fills those fields in too.
///
/// Together with [`patch_phase_status`] this lets the four-line
/// `controller -> patch status -> requeue` flow stay completely
/// out of per-controller code.
pub trait BuildPhaseStatus: StatusFields {
    /// Construct a fresh status value, populating any non-trio fields
    /// (e.g. `last_validated`) from the implementing type's defaults.
    fn build(phase: Self::Phase, message: Option<String>, observed_generation: Option<i64>)
        -> Self;
}

/// Check if a resource's status already matches the desired state.
///
/// Returns `true` when the status phase, message, and observed generation all match,
/// meaning a status patch would be a no-op and should be skipped.
pub fn is_status_unchanged<S: StatusFields>(
    status: Option<&S>,
    phase: &S::Phase,
    message: Option<&str>,
    observed_generation: Option<i64>,
) -> bool {
    status
        .map(|s| {
            s.phase() == phase
                && s.message() == message
                && s.observed_generation() == observed_generation
        })
        .unwrap_or(false)
}

/// Implement `StatusFields` for a CRD status type that has `phase`, `message`,
/// and `observed_generation` fields following the standard Lattice convention.
///
/// The optional second form (`+ build`) also implements [`BuildPhaseStatus`]
/// — use it when the status struct's only fields are exactly the trio,
/// so it can be constructed by [`patch_phase_status`] directly.
macro_rules! impl_status_fields {
    ($status_type:ty, $phase_type:ty) => {
        impl StatusFields for $status_type {
            type Phase = $phase_type;
            fn phase(&self) -> &Self::Phase {
                &self.phase
            }
            fn message(&self) -> Option<&str> {
                self.message.as_deref()
            }
            fn observed_generation(&self) -> Option<i64> {
                self.observed_generation
            }
        }
    };
    ($status_type:ty, $phase_type:ty, + build) => {
        impl_status_fields!($status_type, $phase_type);
        impl BuildPhaseStatus for $status_type {
            fn build(
                phase: $phase_type,
                message: Option<String>,
                observed_generation: Option<i64>,
            ) -> Self {
                Self {
                    phase,
                    message,
                    observed_generation,
                }
            }
        }
    };
}

/// Idempotent status patch — skips the API call when `next` already matches
/// the resource's current status on phase, message, and observed_generation.
///
/// Use [`patch_phase_status`] when the status struct only has the standard
/// trio of fields; this lower-level helper exists for status types with
/// additional fields (like `InfraProviderStatus::last_validated`) where
/// the caller must construct the value itself.
pub async fn patch_status_if_changed<R, S>(
    client: &Client,
    resource: &R,
    previous: Option<&S>,
    next: &S,
    field_manager: &str,
) -> Result<(), ReconcileError>
where
    R: Resource<Scope = k8s_openapi::NamespaceResourceScope>
        + ResourceExt
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    R::DynamicType: Default,
    S: StatusFields + serde::Serialize,
{
    if is_status_unchanged(
        previous,
        next.phase(),
        next.message(),
        next.observed_generation(),
    ) {
        debug!(
            kind = std::any::type_name::<R>(),
            resource = %resource.name_any(),
            "Status unchanged, skipping update"
        );
        return Ok(());
    }
    let name = resource.name_any();
    let namespace = resource.namespace().ok_or_else(|| {
        ReconcileError::Validation(format!(
            "{} missing metadata.namespace",
            std::any::type_name::<R>()
        ))
    })?;
    crate::kube_utils::patch_resource_status::<R>(client, &name, &namespace, next, field_manager)
        .await?;
    Ok(())
}

/// One-call status update for the standard `(phase, message, generation)`
/// status shape: builds the status via [`BuildPhaseStatus`], then dispatches
/// through [`patch_status_if_changed`]. Replaces the per-controller
/// `update_status` clones entirely.
pub async fn patch_phase_status<R, S>(
    client: &Client,
    resource: &R,
    previous: Option<&S>,
    phase: S::Phase,
    message: Option<String>,
    observed_generation: Option<i64>,
    field_manager: &str,
) -> Result<(), ReconcileError>
where
    R: Resource<Scope = k8s_openapi::NamespaceResourceScope>
        + ResourceExt
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    R::DynamicType: Default,
    S: BuildPhaseStatus + serde::Serialize,
{
    let next = S::build(phase, message, observed_generation);
    patch_status_if_changed(client, resource, previous, &next, field_manager).await
}

// `InfraProviderStatus` has an extra `last_validated` field, so it needs a
// hand-written `BuildPhaseStatus` impl below.
impl_status_fields!(InfraProviderStatus, InfraProviderPhase);
impl_status_fields!(LatticeServiceStatus, ServicePhase);
impl_status_fields!(LatticeMeshMemberStatus, MeshMemberPhase);
impl_status_fields!(SecretProviderStatus, SecretProviderPhase);
impl_status_fields!(LatticeJobStatus, JobPhase);
impl_status_fields!(LatticeModelStatus, ModelServingPhase);
impl_status_fields!(BackupStoreStatus, BackupStorePhase);
impl_status_fields!(LatticeClusterBackupStatus, ClusterBackupPhase);
impl_status_fields!(LatticeRestoreStatus, RestorePhase);
impl_status_fields!(DNSProviderStatus, DNSProviderPhase, + build);
impl_status_fields!(ImageProviderStatus, ImageProviderPhase, + build);
impl_status_fields!(CertIssuerStatus, CertIssuerPhase, + build);

impl BuildPhaseStatus for InfraProviderStatus {
    fn build(
        phase: InfraProviderPhase,
        message: Option<String>,
        observed_generation: Option<i64>,
    ) -> Self {
        Self {
            phase,
            message,
            last_validated: Some(chrono::Utc::now().to_rfc3339()),
            observed_generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_when_all_fields_match() {
        let status = InfraProviderStatus {
            phase: InfraProviderPhase::Ready,
            message: None,
            observed_generation: Some(1),
            ..Default::default()
        };
        assert!(is_status_unchanged(
            Some(&status),
            &InfraProviderPhase::Ready,
            None,
            Some(1),
        ));
    }

    #[test]
    fn changed_when_phase_differs() {
        let status = InfraProviderStatus {
            phase: InfraProviderPhase::Ready,
            message: None,
            observed_generation: Some(1),
            ..Default::default()
        };
        assert!(!is_status_unchanged(
            Some(&status),
            &InfraProviderPhase::Failed,
            None,
            Some(1),
        ));
    }

    #[test]
    fn changed_when_generation_differs() {
        let status = InfraProviderStatus {
            phase: InfraProviderPhase::Ready,
            message: None,
            observed_generation: Some(1),
            ..Default::default()
        };
        assert!(!is_status_unchanged(
            Some(&status),
            &InfraProviderPhase::Ready,
            None,
            Some(2),
        ));
    }

    #[test]
    fn changed_when_message_differs() {
        let status = InfraProviderStatus {
            phase: InfraProviderPhase::Ready,
            message: Some("all good".to_string()),
            observed_generation: Some(1),
            ..Default::default()
        };
        assert!(!is_status_unchanged(
            Some(&status),
            &InfraProviderPhase::Ready,
            None,
            Some(1),
        ));
    }

    #[test]
    fn changed_when_status_is_none() {
        assert!(!is_status_unchanged::<InfraProviderStatus>(
            None,
            &InfraProviderPhase::Ready,
            None,
            Some(1),
        ));
    }

    #[test]
    fn works_with_service_status() {
        let status = LatticeServiceStatus {
            phase: ServicePhase::Failed,
            message: Some("validation error".to_string()),
            observed_generation: None,
            ..Default::default()
        };
        assert!(is_status_unchanged(
            Some(&status),
            &ServicePhase::Failed,
            Some("validation error"),
            None,
        ));
    }
}
