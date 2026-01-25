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
use crate::telemetry::{AuditEvent, BlockReason, Decision, AuditLogger};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

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
pub async fn handle_connect(
    req: Request<Incoming>,
    cert_cache: Arc<CertificateCache>,
    policy: Arc<PolicyEngine>,
    hold_manager: Arc<ConnectionHoldManager>,
    headless: bool,
    audit: Arc<AuditLogger>,
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

            establish_tunnel(req, upstream_host, port, cert_cache).await
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
                handle_prompt_domain(req, &host, port, cert_cache, hold_manager, policy, audit)
                    .await
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
    cert_cache: Arc<CertificateCache>,
    hold_manager: Arc<ConnectionHoldManager>,
    policy: Arc<PolicyEngine>,
    audit: Arc<AuditLogger>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    // Park the connection
    let (id, decision_rx) = hold_manager.park(host.to_string(), port);

    info!(
        "Connection {} waiting for decision on {}:{}",
        id, host, port
    );

    // TODO: In Phase 4, send IPC message to TUI here
    // For now in Phase 3, we just wait for the decision (which will timeout)

    // Wait for decision
    match decision_rx.await {
        Ok(ConnectionDecision::Allow) => {
            info!("Connection {} allowed for {}:{}", id, host, port);

            // Record the session decision
            policy.record_decision(host, true);

            // Log the prompt result
            audit.log(AuditEvent::NetworkPrompt {
                domain: host.to_string(),
                decision: Decision::Allow,
                persist: false, // Session only for now
            });

            establish_tunnel(req, host, port, cert_cache).await
        }
        Ok(ConnectionDecision::Block) => {
            info!("Connection {} blocked for {}:{}", id, host, port);

            // Record the session decision
            policy.record_decision(host, false);

            // Log the prompt result
            audit.log(AuditEvent::NetworkPrompt {
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

            audit.log(AuditEvent::NetworkBlock {
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
async fn establish_tunnel(
    req: Request<Incoming>,
    host: &str,
    port: u16,
    cert_cache: Arc<CertificateCache>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    let host = host.to_string();
    let cert_cache = cert_cache.clone();

    // Spawn a task to handle the tunnel after upgrade
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = tunnel_connection(upgraded, &host, port, cert_cache).await {
                    // Don't log as error - connection resets are common
                    debug!("Tunnel ended for {}:{}: {}", host, port, e);
                }
            }
            Err(e) => {
                warn!("HTTP upgrade failed for {}:{}: {}", host, port, e);
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
async fn tunnel_connection(
    upgraded: Upgraded,
    host: &str,
    port: u16,
    cert_cache: Arc<CertificateCache>,
) -> Result<(), ProxyError> {
    debug!("Starting tunnel to {}:{}", host, port);

    // Connect to upstream server first (fail fast)
    let upstream_addr = format!("{}:{}", host, port);
    let upstream = TcpStream::connect(&upstream_addr).await.map_err(|e| {
        ProxyError::UpstreamConnect {
            addr: upstream_addr.clone(),
            message: e.to_string(),
        }
    })?;

    debug!("Connected to upstream {}:{}", host, port);

    // Create TLS connector for upstream
    let tls_connector = create_tls_connector()?;
    let server_name = domain_to_server_name(host)?;

    // TLS handshake with upstream
    let upstream_tls = tls_connector
        .connect(server_name, upstream)
        .await
        .map_err(|e| ProxyError::Tls(format!("Upstream TLS handshake failed: {}", e)))?;

    debug!("TLS established with upstream {}:{}", host, port);

    // Create TLS acceptor for client side with domain hint
    let tls_acceptor = create_tls_acceptor(cert_cache, Some(host.to_string()))?;

    // Accept TLS from client
    // We need to convert the Upgraded to a type that TlsAcceptor can use
    let client_tls = tls_acceptor
        .accept(hyper_util::rt::TokioIo::new(upgraded))
        .await
        .map_err(|e| ProxyError::Tls(format!("Client TLS handshake failed: {}", e)))?;

    debug!("TLS established with client for {}:{}", host, port);

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

    debug!("Tunnel closed for {}:{}", host, port);
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
    headless: bool,
    audit: Arc<AuditLogger>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    // Extract host from the request URI
    let uri = req.uri();
    let host = uri
        .host()
        .ok_or_else(|| ProxyError::InvalidConnect("Missing host in request URI".into()))?;

    debug!("HTTP proxy request to {}", host);

    // Evaluate policy
    let decision = policy.evaluate(host);

    match decision {
        PolicyDecision::Allow { reason, .. } => {
            audit.log(AuditEvent::NetworkAllow {
                domain: host.to_string(),
                reason,
            });

            // Forward the request
            forward_http_request(req).await
        }
        PolicyDecision::Block { reason } => {
            audit.log(AuditEvent::NetworkBlock {
                domain: host.to_string(),
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
                    domain: host.to_string(),
                    reason: BlockReason::PromptTimeout,
                });

                Ok(forbidden_response(&format!(
                    "HTTP request to {} blocked: unknown domain (headless mode)",
                    host
                )))
            } else {
                // In Phase 3, just block with a message
                // Phase 4 will add proper prompting
                audit.log(AuditEvent::NetworkBlock {
                    domain: host.to_string(),
                    reason: BlockReason::PromptTimeout,
                });

                Ok(forbidden_response(&format!(
                    "HTTP request to {} requires approval (not available in Phase 3)",
                    host
                )))
            }
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
