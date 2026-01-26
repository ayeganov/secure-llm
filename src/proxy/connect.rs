//! HTTP CONNECT method handling for HTTPS tunneling.
//!
//! This module handles the HTTP CONNECT method used by clients to establish
//! HTTPS tunnels through the proxy. The flow is:
//!
//! 1. Client sends: `CONNECT api.example.com:443 HTTP/1.1`
//! 2. Proxy evaluates policy for the domain
//! 3. If allowed: Return `200 Connection Established` and upgrade to tunnel
//! 4. If blocked: Return `403 Forbidden`
//! 5. If prompt needed: Hold connection, wait for user decision
//!
//! After the 200 response, we perform TLS interception:
//! 1. Accept TLS from client using our dynamically generated certificate
//! 2. Connect to upstream server with real TLS
//! 3. Forward data bidirectionally between client and upstream
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::proxy::connect::handle_connect;
//!
//! // Called from proxy server when CONNECT request is received
//! let response = handle_connect(
//!     request,
//!     cert_cache,
//!     policy_engine,
//!     hold_manager,
//!     headless,
//! ).await?;
//! ```

use super::error::ProxyError;
use super::hold::{ConnectionDecision, ConnectionHoldManager};
use super::policy::{PolicyDecision, PolicyEngine};
use super::tls::{create_tls_acceptor, create_tls_connector, domain_to_server_name, CertificateCache};
use crate::control::ProxyToTui;
use crate::telemetry::{AuditEvent, BlockReason, Decision, AuditLogger};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// Context for handling domain prompting.
struct PromptContext {
    cert_cache: Arc<CertificateCache>,
    hold_manager: Arc<ConnectionHoldManager>,
    policy: Arc<PolicyEngine>,
    audit: Arc<AuditLogger>,
    control_tx: Option<tokio::sync::mpsc::Sender<crate::control::ProxyToTui>>,
}

/// Handle HTTP CONNECT request for HTTPS tunneling.
///
/// This is the main entry point for CONNECT handling. It evaluates the
/// policy for the target domain and either establishes a tunnel, blocks
/// the connection, or holds it for user decision.
///
/// # Arguments
///
/// * `req` - The HTTP CONNECT request.
/// * `cert_cache` - Certificate cache for TLS interception.
/// * `policy` - Policy engine for domain evaluation.
/// * `hold_manager` - Manager for pending connections.
/// * `headless` - Whether running in headless mode (no TUI prompts).
/// * `audit` - Audit logger for security events.
/// * `control_tx` - Optional channel for sending messages to TUI.
pub async fn handle_connect(
    req: Request<Incoming>,
    cert_cache: Arc<CertificateCache>,
    policy: Arc<PolicyEngine>,
    hold_manager: Arc<ConnectionHoldManager>,
    headless: bool,
    audit: Arc<AuditLogger>,
    control_tx: Option<tokio::sync::mpsc::Sender<crate::control::ProxyToTui>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    // Extract the target host:port from CONNECT request
    let target = req
        .uri()
        .authority()
        .ok_or_else(|| ProxyError::InvalidConnect("Missing authority in CONNECT request".into()))?
        .to_string();

    // Parse host and port
    let (host, port) = parse_host_port(&target)?;

    debug!("CONNECT request to {}:{}", host, port);

    // Evaluate policy for this domain
    let decision = policy.evaluate(&host);

    match decision {
        PolicyDecision::Allow { rewrite_to, reason } => {
            // Domain is allowed - establish tunnel with optional host rewrite
            let upstream_host = rewrite_to.as_deref().unwrap_or(&host);

            // Log the allow decision
            audit.log(AuditEvent::NetworkAllow {
                domain: host.clone(),
                reason: reason.clone(),
            });

            info!(
                "Allowing connection to {} (upstream: {}, reason: {:?})",
                host, upstream_host, reason
            );

            // Pass both original host (for client cert) and upstream host (for connection)
            establish_tunnel(req, &host, upstream_host, port, cert_cache).await
        }
        PolicyDecision::Block { reason } => {
            // Domain is blocked - return 403
            info!("Blocking connection to {}: {:?}", host, reason);

            // Log the block decision
            audit.log(AuditEvent::NetworkBlock {
                domain: host.clone(),
                reason: reason.clone(),
            });

            Ok(forbidden_response(&format!(
                "Connection to {} blocked: {:?}",
                host, reason
            )))
        }
        PolicyDecision::Prompt => {
            // Domain requires user prompt
            if headless {
                // In headless mode, block unknown domains (fail-closed)
                info!("Blocking unknown domain in headless mode: {}", host);

                audit.log(AuditEvent::NetworkBlock {
                    domain: host.clone(),
                    reason: BlockReason::PromptTimeout, // Using timeout as the "no TUI available" reason
                });

                Ok(forbidden_response(&format!(
                    "Connection to {} blocked: unknown domain (headless mode)",
                    host
                )))
            } else {
                // In interactive mode, hold connection pending user decision
                let ctx = PromptContext {
                    cert_cache,
                    hold_manager,
                    policy,
                    audit,
                    control_tx,
                };
                handle_prompt_domain(req, &host, port, ctx).await
            }
        }
    }
}

/// Handle a domain that requires user prompting.
///
/// Parks the connection and waits for a user decision. If approved,
/// establishes the tunnel. If denied or timeout, returns 403.
async fn handle_prompt_domain(
    req: Request<Incoming>,
    host: &str,
    port: u16,
    ctx: PromptContext,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    // Park the connection
    let (id, decision_rx) = ctx.hold_manager.park(host.to_string(), port);

    info!(
        "Connection {} waiting for decision on {}:{}",
        id, host, port
    );

    // Send permission request to TUI via control channel (Phase 4)
    if let Some(ref tx) = ctx.control_tx {
        use crate::control::ProxyToTui;
        let msg = ProxyToTui::PermissionRequest {
            id,
            domain: host.to_string(),
            port,
            timestamp: chrono::Utc::now(),
        };
        // Non-blocking send - if TUI is not available, the request will timeout
        if let Err(e) = tx.try_send(msg) {
            debug!("Failed to send permission request to TUI: {} (TUI may not be running)", e);
        }
    }

    // Wait for decision
    match decision_rx.await {
        Ok(ConnectionDecision::Allow) => {
            info!("Connection {} allowed for {}:{}", id, host, port);

            // Record the session decision
            ctx.policy.record_decision(host, true);

            // Log the prompt result
            ctx.audit.log(AuditEvent::NetworkPrompt {
                domain: host.to_string(),
                decision: Decision::Allow,
                persist: false, // Session only for now
            });

            // Check for host rewrite (approved domains can still be rewritten)
            let upstream_host = ctx.policy.get_rewrite(host).unwrap_or_else(|| host.to_string());
            establish_tunnel(req, host, &upstream_host, port, ctx.cert_cache).await
        }
        Ok(ConnectionDecision::Block) => {
            info!("Connection {} blocked for {}:{}", id, host, port);

            // Record the session decision
            ctx.policy.record_decision(host, false);

            // Log the prompt result
            ctx.audit.log(AuditEvent::NetworkPrompt {
                domain: host.to_string(),
                decision: Decision::Block,
                persist: false,
            });

            Ok(forbidden_response(&format!(
                "Connection to {} blocked by user",
                host
            )))
        }
        Err(_) => {
            // Channel closed (likely timeout or cancel)
            warn!("Connection {} channel closed for {}:{}", id, host, port);

            // Notify TUI that the request was cancelled
            if let Some(ref tx) = ctx.control_tx {
                let msg = ProxyToTui::PermissionCancelled {
                    id,
                    reason: "timeout".to_string(),
                };
                let _ = tx.try_send(msg);
            }

            ctx.audit.log(AuditEvent::NetworkBlock {
                domain: host.to_string(),
                reason: BlockReason::PromptTimeout,
            });

            Ok(forbidden_response(&format!(
                "Connection to {} blocked: decision timeout",
                host
            )))
        }
    }
}

/// Establish a TLS-intercepting tunnel.
///
/// This function:
/// 1. Returns 200 Connection Established
/// 2. Spawns a task to handle the upgraded connection
/// 3. The task performs TLS interception and bidirectional forwarding
///
/// # Arguments
///
/// * `req` - The HTTP CONNECT request to upgrade
/// * `client_host` - The host the client requested (used for certificate generation)
/// * `upstream_host` - The actual host to connect to (may differ due to host rewrite)
/// * `port` - The port to connect to
/// * `cert_cache` - Certificate cache for TLS interception
async fn establish_tunnel(
    req: Request<Incoming>,
    client_host: &str,
    upstream_host: &str,
    port: u16,
    cert_cache: Arc<CertificateCache>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    let client_host = client_host.to_string();
    let upstream_host = upstream_host.to_string();
    let cert_cache = cert_cache.clone();

    // Spawn a task to handle the tunnel after upgrade
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) =
                    tunnel_connection(upgraded, &client_host, &upstream_host, port, cert_cache)
                        .await
                {
                    // Don't log as error - connection resets are common
                    debug!(
                        "Tunnel ended for {} (upstream: {}): {}",
                        client_host, upstream_host, e
                    );
                }
            }
            Err(e) => {
                warn!(
                    "HTTP upgrade failed for {} (upstream: {}): {}",
                    client_host, upstream_host, e
                );
            }
        }
    });

    // Return 200 Connection Established to initiate the upgrade
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .unwrap())
}

/// Handle the actual tunnel after HTTP upgrade.
///
/// This is where TLS interception happens:
/// 1. Connect to upstream server first (to fail fast if unreachable)
/// 2. Perform TLS handshake with upstream
/// 3. Accept TLS from client using dynamically generated cert
/// 4. Forward data bidirectionally
///
/// # Arguments
///
/// * `upgraded` - The upgraded HTTP connection
/// * `client_host` - The host the client requested (used for certificate generation)
/// * `upstream_host` - The actual host to connect to (may differ due to host rewrite)
/// * `port` - The port to connect to
/// * `cert_cache` - Certificate cache for TLS interception
async fn tunnel_connection(
    upgraded: Upgraded,
    client_host: &str,
    upstream_host: &str,
    port: u16,
    cert_cache: Arc<CertificateCache>,
) -> Result<(), ProxyError> {
    debug!(
        "Starting tunnel: client requested {}, connecting to {}:{}",
        client_host, upstream_host, port
    );

    // Connect to upstream server first (fail fast)
    let upstream_addr = format!("{}:{}", upstream_host, port);
    let upstream = TcpStream::connect(&upstream_addr).await.map_err(|e| {
        ProxyError::UpstreamConnect {
            addr: upstream_addr.clone(),
            message: e.to_string(),
        }
    })?;

    debug!("Connected to upstream {}:{}", upstream_host, port);

    // Create TLS connector for upstream
    let tls_connector = create_tls_connector()?;
    let server_name = domain_to_server_name(upstream_host)?;

    // TLS handshake with upstream
    let upstream_tls = tls_connector
        .connect(server_name, upstream)
        .await
        .map_err(|e| ProxyError::Tls(format!("Upstream TLS handshake failed: {}", e)))?;

    debug!("TLS established with upstream {}:{}", upstream_host, port);

    // Create TLS acceptor for client side using the ORIGINAL host the client requested
    // This ensures the client sees a certificate for the domain it asked for,
    // even if we're actually connecting to a different upstream (host rewrite)
    let tls_acceptor = create_tls_acceptor(cert_cache, Some(client_host.to_string()))?;

    // Accept TLS from client
    // We need to convert the Upgraded to a type that TlsAcceptor can use
    let client_tls = tls_acceptor
        .accept(hyper_util::rt::TokioIo::new(upgraded))
        .await
        .map_err(|e| ProxyError::Tls(format!("Client TLS handshake failed: {}", e)))?;

    debug!("TLS established with client for {}", client_host);

    // Bidirectional copy between client and upstream
    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_tls);

    // Use select to handle bidirectional copy
    // When either direction closes or errors, we're done
    let client_to_upstream = async {
        tokio::io::copy(&mut client_read, &mut upstream_write).await
    };

    let upstream_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut client_write).await
    };

    tokio::select! {
        result = client_to_upstream => {
            if let Err(e) = result {
                debug!("Client->upstream copy ended: {}", e);
            }
        }
        result = upstream_to_client => {
            if let Err(e) = result {
                debug!("Upstream->client copy ended: {}", e);
            }
        }
    }

    debug!(
        "Tunnel closed for {} (upstream: {})",
        client_host, upstream_host
    );
    Ok(())
}

/// Parse host:port string from CONNECT authority.
///
/// Examples:
/// - `api.example.com:443` -> ("api.example.com", 443)
/// - `api.example.com` -> ("api.example.com", 443) (default port)
fn parse_host_port(authority: &str) -> Result<(String, u16), ProxyError> {
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        // Check if this is an IPv6 address like [::1]:443
        if host.starts_with('[') && host.ends_with(']') {
            let port = port_str.parse::<u16>().map_err(|_| {
                ProxyError::InvalidConnect(format!("Invalid port: {}", port_str))
            })?;
            // Remove brackets from IPv6 address
            let ipv6_host = &host[1..host.len() - 1];
            return Ok((ipv6_host.to_string(), port));
        }

        // Regular host:port
        let port = port_str.parse::<u16>().map_err(|_| {
            ProxyError::InvalidConnect(format!("Invalid port: {}", port_str))
        })?;
        Ok((host.to_string(), port))
    } else {
        // No port specified - default to 443 for CONNECT
        Ok((authority.to_string(), 443))
    }
}

/// Create an empty response body.
fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Create a response body with content.
fn full_body(content: String) -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::from(content))
        .map_err(|never| match never {})
        .boxed()
}

/// Create a 403 Forbidden response.
fn forbidden_response(message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "text/plain")
        .body(full_body(message.to_string()))
        .unwrap()
}

/// Handle plain HTTP proxy request (non-CONNECT).
///
/// This forwards HTTP requests that don't use CONNECT tunneling.
/// Some older clients or package managers may use plain HTTP.
pub async fn handle_http(
    req: Request<Incoming>,
    policy: Arc<PolicyEngine>,
    hold_manager: Arc<ConnectionHoldManager>,
    headless: bool,
    audit: Arc<AuditLogger>,
    control_tx: Option<tokio::sync::mpsc::Sender<crate::control::ProxyToTui>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    // Extract host from the request URI (clone to avoid borrow issues)
    let host = req
        .uri()
        .host()
        .ok_or_else(|| ProxyError::InvalidConnect("Missing host in request URI".into()))?
        .to_string();

    debug!("HTTP proxy request to {}", host);

    // Evaluate policy
    let decision = policy.evaluate(&host);

    match decision {
        PolicyDecision::Allow { reason, .. } => {
            audit.log(AuditEvent::NetworkAllow {
                domain: host.clone(),
                reason,
            });

            // Forward the request
            forward_http_request(req).await
        }
        PolicyDecision::Block { reason } => {
            audit.log(AuditEvent::NetworkBlock {
                domain: host.clone(),
                reason,
            });

            Ok(forbidden_response(&format!(
                "HTTP request to {} blocked",
                host
            )))
        }
        PolicyDecision::Prompt => {
            if headless {
                audit.log(AuditEvent::NetworkBlock {
                    domain: host.clone(),
                    reason: BlockReason::PromptTimeout,
                });

                Ok(forbidden_response(&format!(
                    "HTTP request to {} blocked: unknown domain (headless mode)",
                    host
                )))
            } else {
                // Hold connection pending user decision
                handle_prompt_http(req, &host, hold_manager, policy, audit, control_tx).await
            }
        }
    }
}

/// Handle an HTTP request that requires user permission.
async fn handle_prompt_http(
    req: Request<Incoming>,
    host: &str,
    hold_manager: Arc<ConnectionHoldManager>,
    policy: Arc<PolicyEngine>,
    audit: Arc<AuditLogger>,
    control_tx: Option<tokio::sync::mpsc::Sender<crate::control::ProxyToTui>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    use crate::control::ProxyToTui;
    use crate::proxy::hold::ConnectionDecision;

    // Park the connection, waiting for a decision
    let (id, decision_rx) = hold_manager.park(host.to_string(), 80);

    info!(
        "HTTP connection {} waiting for decision on {}",
        id, host
    );

    // Send permission request to TUI via control channel
    if let Some(ref tx) = control_tx {
        let msg = ProxyToTui::PermissionRequest {
            id,
            domain: host.to_string(),
            port: 80,
            timestamp: chrono::Utc::now(),
        };
        // Non-blocking send - if TUI is not available, the request will timeout
        if let Err(e) = tx.try_send(msg) {
            debug!("Failed to send HTTP permission request to TUI: {} (TUI may not be running)", e);
        }
    }

    // Wait for decision
    match decision_rx.await {
        Ok(ConnectionDecision::Allow) => {
            info!("HTTP connection {} allowed for {}", id, host);

            // Record the session decision
            policy.record_decision(host, true);

            // Log the prompt result
            audit.log(AuditEvent::NetworkPrompt {
                domain: host.to_string(),
                decision: Decision::Allow,
                persist: false,
            });

            // Forward the request
            forward_http_request(req).await
        }
        Ok(ConnectionDecision::Block) => {
            info!("HTTP connection {} blocked for {}", id, host);

            // Record the session decision
            policy.record_decision(host, false);

            // Log the prompt result
            audit.log(AuditEvent::NetworkPrompt {
                domain: host.to_string(),
                decision: Decision::Block,
                persist: false,
            });

            Ok(forbidden_response(&format!(
                "HTTP request to {} blocked by user",
                host
            )))
        }
        Err(_) => {
            // Channel closed (likely timeout or cancel)
            warn!("HTTP connection {} channel closed for {}", id, host);

            // Notify TUI that the request was cancelled
            if let Some(ref tx) = control_tx {
                let msg = ProxyToTui::PermissionCancelled {
                    id,
                    reason: "timeout".to_string(),
                };
                let _ = tx.try_send(msg);
            }

            audit.log(AuditEvent::NetworkBlock {
                domain: host.to_string(),
                reason: BlockReason::PromptTimeout,
            });

            Ok(forbidden_response(&format!(
                "HTTP request to {} blocked: decision timeout",
                host
            )))
        }
    }
}

/// Forward an HTTP request to the upstream server.
async fn forward_http_request(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<_, Incoming> = Client::builder(TokioExecutor::new()).build_http();

    let response = client
        .request(req)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            addr: "upstream".to_string(),
            message: e.to_string(),
        })?;

    // Convert the response body
    Ok(response.map(|body| body.boxed()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_with_port() {
        let (host, port) = parse_host_port("api.example.com:443").unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_custom_port() {
        let (host, port) = parse_host_port("api.example.com:8443").unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_host_port_default() {
        let (host, port) = parse_host_port("api.example.com").unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_invalid_port() {
        let result = parse_host_port("api.example.com:invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[::1]:443").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_forbidden_response() {
        let response = forbidden_response("test message");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
