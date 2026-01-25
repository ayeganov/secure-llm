//! Network proxy module for TLS interception and policy enforcement.
//!
//! This module provides an embedded MITM proxy with:
//! - HTTP CONNECT method handling for HTTPS tunneling
//! - SNI extraction from TLS ClientHello
//! - Dynamic certificate generation for TLS interception
//! - Domain policy enforcement (allowlist/blocklist/graylist)
//! - Host rewriting for LLM gateway redirection
//! - Connection hold/resume for unknown domains pending user decision
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Sandbox (Network NS)                      │
//! │  ┌─────────────┐                                            │
//! │  │  IDE/Agent  │─────────────────────────────────┐          │
//! │  └─────────────┘                                 │          │
//! │                                                  │          │
//! │                                                  ▼          │
//! │                                         ┌──────────────┐    │
//! │                                         │    Proxy     │    │
//! │                                         │  (10.200.0.1)│    │
//! │                                         └──────┬───────┘    │
//! └────────────────────────────────────────────────┼────────────┘
//!                                                  │
//!                                                  ▼
//!                                         ┌──────────────┐
//!                                         │   Internet   │
//!                                         │  (via veth)  │
//!                                         └──────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::proxy::{ProxyServer, ProxyConfig, PolicyEngine};
//! use secure_llm::sandbox::ca::EphemeralCa;
//! use std::sync::Arc;
//!
//! // Create dependencies
//! let ca = Arc::new(EphemeralCa::generate()?);
//! let policy = Arc::new(PolicyEngine::from_config(&config.network, &[]));
//!
//! // Create and run proxy
//! let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
//! let server = ProxyServer::new(ProxyConfig { /* ... */ }, shutdown_rx);
//! server.run().await?;
//! ```

pub mod connect;
pub mod error;
pub mod hold;
pub mod policy;
pub mod server;
pub mod tls;

// Re-export main types for convenient access
pub use error::ProxyError;
pub use hold::{ConnectionDecision, ConnectionHoldManager, HoldError, PendingInfo};
pub use policy::{PolicyDecision, PolicyEngine};
pub use server::{ProxyConfig, ProxyServer, ProxyServerBuilder};
pub use tls::{CertificateCache, create_tls_acceptor, create_tls_connector};
