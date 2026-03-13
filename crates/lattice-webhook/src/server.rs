//! Axum HTTPS server with rustls TLS configuration
//!
//! Binds on 0.0.0.0:9443 using the webhook TLS credentials and serves
//! the /validate endpoint.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;

use crate::certs::WebhookTls;
use crate::error::Error;
use crate::handler::{validate_handler, HandlerState};
use crate::validators::ValidatorRegistry;

use lattice_common::DEFAULT_WEBHOOK_PORT as WEBHOOK_PORT;

/// Build the Axum router with the /validate endpoint
pub(crate) fn build_router(registry: ValidatorRegistry) -> Router {
    let state = Arc::new(HandlerState { registry });
    Router::new()
        .route("/validate", post(validate_handler))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)) // 1 MiB — admission reviews are bounded
        .with_state(state)
}

/// Start the HTTPS webhook server
///
/// Binds on 0.0.0.0:9443 with the provided TLS credentials and serves
/// admission validation requests.
pub async fn serve(tls: WebhookTls) -> Result<(), Error> {
    let router = build_router(ValidatorRegistry::new());
    let addr = SocketAddr::from(([0, 0, 0, 0], WEBHOOK_PORT));

    let rustls_config = RustlsConfig::from_pem(tls.cert_pem.into_bytes(), tls.key_pem.into_bytes())
        .await
        .map_err(|e| Error::Tls(format!("failed to create rustls config: {e}")))?;

    tracing::info!(port = WEBHOOK_PORT, "Starting admission webhook server");

    axum_server::bind_rustls(addr, rustls_config)
        .serve(router.into_make_service())
        .await
        .map_err(|e| Error::Server(format!("webhook server error: {e}")))?;

    Ok(())
}
