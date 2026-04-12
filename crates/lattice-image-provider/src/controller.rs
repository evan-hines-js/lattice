//! ImageProvider reconciliation controller
//!
//! Watches ImageProvider CRDs and creates ESO ExternalSecrets that produce
//! `kubernetes.io/dockerconfigjson` Secrets for image pull authentication.
//!
//! Uses the same `ensure_credentials` path as InfraProvider and DNSProvider.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Api, Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::status_check;
use lattice_common::{
    ControllerContext, ReconcileError, LABEL_MANAGED_BY, OPERATOR_NAME, REQUEUE_ERROR_SECS,
    REQUEUE_SUCCESS_SECS,
};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_crd::crd::{
    EgressRule, EgressTarget, ImageProvider, ImageProviderPhase, ImageProviderStatus,
    LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberTarget, ParsedEndpoint,
};

const FIELD_MANAGER: &str = "lattice-image-provider-controller";

/// Reconcile an ImageProvider
///
/// Validates the spec and syncs credentials via ESO. The resulting Secret
/// is a `kubernetes.io/dockerconfigjson` type that kubelet uses for image pulls.
pub async fn reconcile(
    ip: Arc<ImageProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = ip.name_any();
    let client = &ctx.client;
    let generation = ip.metadata.generation.ok_or_else(|| {
        ReconcileError::Validation("ImageProvider missing metadata.generation".into())
    })?;

    if status_check::is_status_unchanged(
        ip.status.as_ref(),
        &ImageProviderPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    info!(image_provider = %name, provider_type = ?ip.spec.provider_type, "Reconciling ImageProvider");

    if let Err(e) = ip.spec.validate() {
        let msg = e.to_string();
        warn!(image_provider = %name, error = %msg, "Validation failed");
        update_status(
            client,
            &ip,
            ImageProviderPhase::Failed,
            Some(msg),
            Some(generation),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    if let Some(ref credentials) = ip.spec.credentials {
        // Force dockerconfigjson type so kubelet recognizes the Secret
        let mut creds = credentials.clone();
        if creds.secret_type.is_none() {
            creds.secret_type = Some(lattice_core::SECRET_TYPE_DOCKERCONFIG.to_string());
        }

        // Interpolate ${registry} in credentialData if provided
        let interpolated;
        let credential_data = match ip.spec.credential_data.as_ref() {
            Some(data) => {
                interpolated = interpolate_registry(data, &ip.spec.registry)
                    .map_err(ReconcileError::Validation)?;
                Some(&interpolated)
            }
            None => None,
        };

        if let Err(e) = lattice_secret_provider::credentials::reconcile_credentials(
            client,
            &lattice_secret_provider::credentials::ProviderCredentialConfig {
                provider_name: &name,
                credentials: &creds,
                credential_data,
                target_namespace: LATTICE_SYSTEM_NAMESPACE,
                field_manager: FIELD_MANAGER,
            },
        )
        .await
        {
            let msg = format!("Failed to create ExternalSecret: {e}");
            warn!(image_provider = %name, error = %msg);
            update_status(
                client,
                &ip,
                ImageProviderPhase::Failed,
                Some(msg),
                Some(generation),
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    }

    // Sync trust authority cosign public keys via ESO
    if let Some(ref trust) = ip.spec.trust {
        for authority in &trust.authorities {
            let key_secret_name = format!("{}-trust-{}", name, authority.name);
            if let Err(e) = lattice_secret_provider::credentials::reconcile_credentials(
                client,
                &lattice_secret_provider::credentials::ProviderCredentialConfig {
                    provider_name: &key_secret_name,
                    credentials: &authority.key,
                    credential_data: None,
                    target_namespace: LATTICE_SYSTEM_NAMESPACE,
                    field_manager: FIELD_MANAGER,
                },
            )
            .await
            {
                let msg = format!(
                    "Failed to sync trust authority '{}' key: {e}",
                    authority.name
                );
                warn!(image_provider = %name, error = %msg);
                update_status(
                    client,
                    &ip,
                    ImageProviderPhase::Failed,
                    Some(msg),
                    Some(generation),
                )
                .await?;
                return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
            }
        }
    }

    // Ensure the operator can reach the registry for signature verification
    if let Err(e) = ensure_registry_egress_lmm(client, &ip).await {
        warn!(image_provider = %name, error = %e, "Failed to ensure registry egress LMM");
    }

    let status_msg = if ip.spec.credentials.is_some() {
        "Credentials synced"
    } else if ip.spec.trust.is_some() {
        "Trust policy configured"
    } else {
        "Ready (no credentials configured)"
    };
    info!(image_provider = %name, "{status_msg}");
    update_status(
        client,
        &ip,
        ImageProviderPhase::Ready,
        Some(status_msg.to_string()),
        Some(generation),
    )
    .await?;

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
}

/// Interpolate `${registry}` in credentialData values with the actual registry hostname.
///
/// Returns an error if the registry value contains Go template syntax (`{{`/`}}`),
/// which could be used to inject into ESO's Go template engine and exfiltrate
/// other secret values.
fn interpolate_registry(
    data: &std::collections::BTreeMap<String, String>,
    registry: &str,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    if registry.contains("{{") || registry.contains("}}") {
        return Err(format!(
            "registry '{}' contains Go template syntax, which is not allowed",
            registry
        ));
    }
    Ok(data
        .iter()
        .map(|(k, v)| (k.clone(), v.replace("${registry}", registry)))
        .collect())
}

/// Ensure an egress LMM exists so the operator can reach the registry for
/// cosign signature verification.
///
/// When an ImageProvider has `trust.enforce: true`, the operator needs to
/// reach the registry to fetch signature manifests. This creates a lightweight
/// egress-only LatticeMeshMember targeting operator pods. Without it, the
/// mesh (Cilium CNP + Istio ServiceEntry) blocks the connection.
///
/// If trust is not enforced (or removed), any existing egress LMM is deleted.
async fn ensure_registry_egress_lmm(
    client: &Client,
    ip: &ImageProvider,
) -> Result<(), ReconcileError> {
    let ip_name = ip.name_any();
    let lmm_name = format!("egress-ip-{}", ip_name);
    let api: Api<LatticeMeshMember> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    let needs_egress = ip.spec.trust.as_ref().map(|t| t.enforce).unwrap_or(false);

    if !needs_egress {
        match api.delete(&lmm_name, &Default::default()).await {
            Ok(_) => {
                debug!(image_provider = %ip_name, "Deleted registry egress LMM (trust not enforced)");
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => {
                warn!(image_provider = %ip_name, error = %e, "Failed to delete registry egress LMM");
            }
        }
        return Ok(());
    }

    let ep = parse_registry_endpoint(&ip.spec.registry, ip.spec.insecure);

    let mut lmm = LatticeMeshMember::new(
        &lmm_name,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                OPERATOR_NAME.to_string(),
            )])),
            ports: vec![],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![EgressRule::tcp(
                EgressTarget::for_host(&ep.host),
                vec![ep.port],
            )],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: Some(OPERATOR_NAME.to_string()),
            ambient: true,
            advertise: None,
        },
    );
    lmm.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    lmm.metadata.labels = Some(BTreeMap::from([(
        LABEL_MANAGED_BY.to_string(),
        "image-provider-controller".to_string(),
    )]));

    let params = PatchParams::apply(FIELD_MANAGER).force();
    api.patch(&lmm_name, &params, &Patch::Apply(&lmm)).await?;

    info!(
        image_provider = %ip_name,
        lmm = %lmm_name,
        host = %ep.host,
        port = ep.port,
        "Ensured egress LMM for image registry signature verification"
    );
    Ok(())
}

/// Parse a registry string (e.g., "ghcr.io", "10.0.0.131:5557") into host and port.
///
/// The `insecure` flag from the ImageProvider spec determines the protocol:
/// insecure=true → HTTP (default port 80), insecure=false → HTTPS (default port 443).
/// If the registry string includes an explicit port, that takes precedence.
fn parse_registry_endpoint(registry: &str, insecure: bool) -> ParsedEndpoint {
    let (protocol, default_port) = if insecure {
        ("http", 80u16)
    } else {
        ("https", 443u16)
    };

    // Try ParsedEndpoint::parse with protocol prefix
    if let Some(ep) = ParsedEndpoint::parse(&format!("{}://{}", protocol, registry)) {
        return ep;
    }

    // Fallback: split host:port manually
    if let Some((host, port_str)) = registry.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return ParsedEndpoint {
                protocol: protocol.to_string(),
                host: host.to_string(),
                port,
                url: format!("{}://{}", protocol, registry),
            };
        }
    }

    // No explicit port — use protocol default
    ParsedEndpoint {
        protocol: protocol.to_string(),
        host: registry.to_string(),
        port: default_port,
        url: format!("{}://{}", protocol, registry),
    }
}

async fn update_status(
    client: &Client,
    ip: &ImageProvider,
    phase: ImageProviderPhase,
    message: Option<String>,
    observed_generation: Option<i64>,
) -> Result<(), ReconcileError> {
    if status_check::is_status_unchanged(
        ip.status.as_ref(),
        &phase,
        message.as_deref(),
        observed_generation,
    ) {
        debug!(image_provider = %ip.name_any(), "Status unchanged, skipping update");
        return Ok(());
    }

    let name = ip.name_any();
    let namespace = ip.namespace().ok_or_else(|| {
        ReconcileError::Validation("ImageProvider missing metadata.namespace".into())
    })?;

    let status = ImageProviderStatus {
        phase,
        message,
        observed_generation,
    };

    lattice_common::kube_utils::patch_resource_status::<ImageProvider>(
        client,
        &name,
        &namespace,
        &status,
        FIELD_MANAGER,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_crd::crd::{ImageProviderSpec, ImageProviderType};

    fn sample_provider(provider_type: ImageProviderType, registry: &str) -> ImageProvider {
        ImageProvider::new("test", ImageProviderSpec::new(provider_type, registry))
    }

    #[test]
    fn parse_registry_ip_with_port_insecure() {
        let ep = super::parse_registry_endpoint("10.0.0.131:5557", true);
        assert_eq!(ep.host, "10.0.0.131");
        assert_eq!(ep.port, 5557);
        assert_eq!(ep.protocol, "http");
    }

    #[test]
    fn parse_registry_hostname_no_port_secure() {
        let ep = super::parse_registry_endpoint("ghcr.io", false);
        assert_eq!(ep.host, "ghcr.io");
        assert_eq!(ep.port, 443);
        assert_eq!(ep.protocol, "https");
    }

    #[test]
    fn parse_registry_hostname_no_port_insecure() {
        let ep = super::parse_registry_endpoint("registry.local", true);
        assert_eq!(ep.host, "registry.local");
        assert_eq!(ep.port, 80);
        assert_eq!(ep.protocol, "http");
    }

    #[test]
    fn parse_registry_hostname_with_port() {
        let ep = super::parse_registry_endpoint("registry.example.com:5000", false);
        assert_eq!(ep.host, "registry.example.com");
        assert_eq!(ep.port, 5000);
    }

    #[test]
    fn generic_provider_validates() {
        let ip = sample_provider(ImageProviderType::Generic, "registry.example.com");
        assert!(ip.spec.validate().is_ok());
    }

    #[test]
    fn empty_registry_fails() {
        let ip = sample_provider(ImageProviderType::Ghcr, "");
        assert!(ip.spec.validate().is_err());
    }

    #[test]
    fn status_unchanged_skips() {
        let mut ip = sample_provider(ImageProviderType::Ghcr, "ghcr.io");
        ip.status = Some(ImageProviderStatus {
            phase: ImageProviderPhase::Ready,
            message: None,
            observed_generation: Some(1),
        });

        assert!(status_check::is_status_unchanged(
            ip.status.as_ref(),
            &ImageProviderPhase::Ready,
            None,
            Some(1)
        ));
    }
}
