//! HTTP proxy server implementation.
//!
//! This module provides the main proxy server that:
//! - Listens for connections from the sandbox via Unix socket
//! - Handles HTTP CONNECT for HTTPS tunneling
//! - Handles plain HTTP requests
//! - Integrates policy evaluation
//! - Manages connection hold/resume for unknown domains
//!
//! # Architecture
//!
//! The proxy uses hyper's HTTP/1.1 server with upgrade support for CONNECT.
//! Each connection is handled in a separate Tokio task.
//!
//! In the rootless socket shim architecture, the proxy listens on a Unix socket
//! that is bind-mounted into the sandbox. Inside the sandbox, an egress shim
//! forwards TCP traffic from 127.0.0.1:8080 to this Unix socket.
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::proxy::{ProxyServer, ProxyConfig};
//! use std::sync::Arc;
//! use std::path::PathBuf;
//!
//! let config = ProxyConfig {
//!     listen_path: PathBuf::from("/tmp/secure-llm/proxy.sock"),
//!     /* ... */
//! };
//! let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
//!
//! let server = ProxyServer::new(config, shutdown_rx);
//! server.run().await?;
//!
//! // To shutdown:
//! shutdown_tx.send(true)?;
//! ```

use super::connect::{handle_connect, handle_http};
use super::error::ProxyError;
use super::hold::ConnectionHoldManager;
use super::policy::PolicyEngine;
use super::tls::CertificateCache;
use crate::sandbox::ca::EphemeralCa;
use crate::telemetry::AuditLogger;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Configuration for the proxy server.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Path to Unix socket to listen on.
    ///
    /// This socket is bind-mounted into the sandbox and accessed by the
    /// egress shim that forwards TCP traffic from 127.0.0.1:8080.
    pub listen_path: PathBuf,
    /// Reference to the ephemeral CA for TLS interception.
    pub ca: Arc<EphemeralCa>,
    /// Policy engine for domain evaluation.
    pub policy: Arc<PolicyEngine>,
    /// Whether to operate in headless mode (fail-closed for unknown domains).
    pub headless: bool,
    /// Timeout for pending connection decisions.
    pub prompt_timeout: Duration,
    /// Reference to the audit logger.
    pub audit: Arc<AuditLogger>,
}

/// The main proxy server.
pub struct ProxyServer {
    config: ProxyConfig,
    /// Shutdown signal receiver.
    shutdown_rx: watch::Receiver<bool>,
    /// Certificate cache for TLS interception.
    cert_cache: Arc<CertificateCache>,
    /// Connection hold manager for pending decisions.
    hold_manager: Arc<ConnectionHoldManager>,
}

impl ProxyServer {
    /// Create a new proxy server.
    ///
    /// # Arguments
    ///
    /// * `config` - Proxy configuration.
    /// * `shutdown_rx` - Receiver for shutdown signal.
    pub fn new(config: ProxyConfig, shutdown_rx: watch::Receiver<bool>) -> Self {
        let cert_cache = Arc::new(CertificateCache::new(config.ca.clone()));
        let hold_manager = Arc::new(ConnectionHoldManager::new(config.prompt_timeout));

        Self {
            config,
            shutdown_rx,
            cert_cache,
            hold_manager,
        }
    }

    /// Get a reference to the connection hold manager.
    ///
    /// This can be used by the TUI to list pending connections and
    /// make decisions.
    pub fn hold_manager(&self) -> Arc<ConnectionHoldManager> {
        self.hold_manager.clone()
    }

    /// Get a reference to the certificate cache.
    pub fn cert_cache(&self) -> Arc<CertificateCache> {
        self.cert_cache.clone()
    }

    /// Run the proxy server.
    ///
    /// This spawns tasks that:
    /// 1. Listen for connections on Unix socket and handle them
    /// 2. Clean up timed-out pending connections
    ///
    /// Returns when the shutdown signal is received.
    pub async fn run(self) -> Result<(), ProxyError> {
        // Ensure parent directory exists
        if let Some(parent) = self.config.listen_path.parent() {
            fs::create_dir_all(parent).map_err(|e| ProxyError::Io(e))?;
        }

        // Remove existing socket file if present
        if self.config.listen_path.exists() {
            fs::remove_file(&self.config.listen_path).map_err(|e| ProxyError::Io(e))?;
        }

        // Bind Unix socket
        let listener = UnixListener::bind(&self.config.listen_path)?;

        // Set socket permissions to 0600 (user only)
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&self.config.listen_path, permissions)
            .map_err(|e| ProxyError::Io(e))?;

        info!("Proxy listening on {:?}", self.config.listen_path);

        // Store path for cleanup
        let listen_path = self.config.listen_path.clone();

        // Spawn timeout cleanup task
        let cleanup_handle = self.spawn_timeout_cleanup();

        // Accept loop
        let mut shutdown_rx = self.shutdown_rx.clone();
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            debug!("Accepted connection on Unix socket");
                            self.spawn_connection_handler(stream);
                        }
                        Err(e) => {
                            warn!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Proxy shutting down");
                        break;
                    }
                }
            }
        }

        // Clean up
        cleanup_handle.abort();

        // Remove socket file on shutdown
        if let Err(e) = fs::remove_file(&listen_path) {
            warn!("Failed to remove socket file: {}", e);
        }

        Ok(())
    }

    /// Spawn a task to handle a single connection.
    fn spawn_connection_handler(&self, stream: tokio::net::UnixStream) {
        let cert_cache = self.cert_cache.clone();
        let policy = self.config.policy.clone();
        let hold_manager = self.hold_manager.clone();
        let headless = self.config.headless;
        let audit = self.config.audit.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, cert_cache, policy, hold_manager, headless, audit)
                    .await
            {
                // Don't log connection resets as errors - they're common
                let err_str = e.to_string();
                if err_str.contains("connection reset")
                    || err_str.contains("broken pipe")
                    || err_str.contains("Connection reset")
                {
                    debug!("Connection ended: {}", e);
                } else {
                    warn!("Connection error: {}", e);
                }
            }
        });
    }

    /// Spawn a task to periodically clean up timed-out connections.
    fn spawn_timeout_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let hold_manager = self.hold_manager.clone();
        let audit = self.config.audit.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let timed_out = hold_manager.cleanup_timeouts();
                        for (domain, _port) in timed_out {
                            // Log timeout events
                            audit.log(crate::telemetry::AuditEvent::NetworkBlock {
                                domain,
                                reason: crate::telemetry::BlockReason::PromptTimeout,
                            });
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        })
    }
}

/// Handle a single client connection.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    cert_cache: Arc<CertificateCache>,
    policy: Arc<PolicyEngine>,
    hold_manager: Arc<ConnectionHoldManager>,
    headless: bool,
    audit: Arc<AuditLogger>,
) -> Result<(), ProxyError> {
    let io = TokioIo::new(stream);

    // Create the service that handles each request
    let service = service_fn(move |req: Request<Incoming>| {
        let cert_cache = cert_cache.clone();
        let policy = policy.clone();
        let hold_manager = hold_manager.clone();
        let audit = audit.clone();

        async move {
            proxy_request(req, cert_cache, policy, hold_manager, headless, audit).await
        }
    });

    // Serve HTTP/1.1 with support for upgrades (needed for CONNECT)
    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .map_err(ProxyError::from)
}

/// Process a single proxy request.
async fn proxy_request(
    req: Request<Incoming>,
    cert_cache: Arc<CertificateCache>,
    policy: Arc<PolicyEngine>,
    hold_manager: Arc<ConnectionHoldManager>,
    headless: bool,
    audit: Arc<AuditLogger>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
    if req.method() == Method::CONNECT {
        // HTTPS tunneling via CONNECT
        handle_connect(req, cert_cache, policy, hold_manager, headless, audit).await
    } else {
        // Plain HTTP proxying
        handle_http(req, policy, headless, audit).await
    }
}

/// Builder for ProxyServer configuration.
pub struct ProxyServerBuilder {
    listen_path: Option<PathBuf>,
    ca: Option<Arc<EphemeralCa>>,
    policy: Option<Arc<PolicyEngine>>,
    headless: bool,
    prompt_timeout: Duration,
    audit: Option<Arc<AuditLogger>>,
}

impl ProxyServerBuilder {
    /// Create a new builder with defaults.
    pub fn new() -> Self {
        Self {
            listen_path: None,
            ca: None,
            policy: None,
            headless: false,
            prompt_timeout: Duration::from_secs(30),
            audit: None,
        }
    }

    /// Set the listen path (Unix socket).
    pub fn listen_path(mut self, path: PathBuf) -> Self {
        self.listen_path = Some(path);
        self
    }

    /// Set the ephemeral CA.
    pub fn ca(mut self, ca: Arc<EphemeralCa>) -> Self {
        self.ca = Some(ca);
        self
    }

    /// Set the policy engine.
    pub fn policy(mut self, policy: Arc<PolicyEngine>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set headless mode.
    pub fn headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
    }

    /// Set the prompt timeout.
    pub fn prompt_timeout(mut self, timeout: Duration) -> Self {
        self.prompt_timeout = timeout;
        self
    }

    /// Set the audit logger.
    pub fn audit(mut self, audit: Arc<AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Build the proxy server.
    ///
    /// # Arguments
    ///
    /// * `shutdown_rx` - Receiver for shutdown signal.
    ///
    /// # Panics
    ///
    /// Panics if required fields are not set.
    pub fn build(self, shutdown_rx: watch::Receiver<bool>) -> ProxyServer {
        let config = ProxyConfig {
            listen_path: self.listen_path.expect("listen_path is required"),
            ca: self.ca.expect("ca is required"),
            policy: self.policy.expect("policy is required"),
            headless: self.headless,
            prompt_timeout: self.prompt_timeout,
            audit: self.audit.expect("audit is required"),
        };

        ProxyServer::new(config, shutdown_rx)
    }
}

impl Default for ProxyServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;
    use std::collections::HashMap;

    fn create_test_config() -> (ProxyConfig, watch::Receiver<bool>) {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let network_config = NetworkConfig {
            allowlist: vec!["allowed.com".to_string()],
            blocklist: vec!["blocked.com".to_string()],
            graylist: vec![],
            host_rewrite: HashMap::new(),
        };
        let policy = Arc::new(PolicyEngine::from_config(&network_config, &[]));
        let audit = Arc::new(AuditLogger::new_null());

        let config = ProxyConfig {
            listen_path: PathBuf::from("/tmp/secure-llm-test.sock"),
            ca,
            policy,
            headless: true,
            prompt_timeout: Duration::from_secs(30),
            audit,
        };

        let (_, rx) = watch::channel(false);
        (config, rx)
    }

    #[test]
    fn test_proxy_server_creation() {
        let (config, shutdown_rx) = create_test_config();
        let server = ProxyServer::new(config, shutdown_rx);

        assert!(server.cert_cache.is_empty());
        assert_eq!(server.hold_manager.pending_count(), 0);
    }

    #[test]
    fn test_proxy_server_builder() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let network_config = NetworkConfig::default();
        let policy = Arc::new(PolicyEngine::from_config(&network_config, &[]));
        let audit = Arc::new(AuditLogger::new_null());
        let (_, shutdown_rx) = watch::channel(false);

        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("proxy.sock");

        let server = ProxyServerBuilder::new()
            .listen_path(socket_path)
            .ca(ca)
            .policy(policy)
            .headless(true)
            .prompt_timeout(Duration::from_secs(60))
            .audit(audit)
            .build(shutdown_rx);

        assert!(server.config.headless);
        assert_eq!(server.config.prompt_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_hold_manager_access() {
        let (config, shutdown_rx) = create_test_config();
        let server = ProxyServer::new(config, shutdown_rx);

        let manager1 = server.hold_manager();
        let manager2 = server.hold_manager();

        // Should be the same Arc
        assert!(Arc::ptr_eq(&manager1, &manager2));
    }
}
