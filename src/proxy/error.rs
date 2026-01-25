//! Error types for proxy operations.
//!
//! This module defines structured error types for the MITM proxy:
//! - Server errors (binding, accept)
//! - TLS errors (certificate generation, handshake)
//! - Connection errors (upstream connection, forwarding)
//! - Policy errors (evaluation failures)

use thiserror::Error;

/// Unified error type for proxy operations.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// I/O error (socket operations, file access).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Hyper HTTP error.
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::Error),

    /// Invalid CONNECT request.
    #[error("Invalid CONNECT request: {0}")]
    InvalidConnect(String),

    /// TLS error during handshake or certificate operations.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Certificate generation failed.
    #[error("Certificate generation failed: {0}")]
    CertGeneration(#[from] crate::sandbox::error::CaError),

    /// Policy evaluation failed.
    #[error("Policy error: {0}")]
    Policy(String),

    /// Connection timeout.
    #[error("Connection timeout")]
    Timeout,

    /// Failed to connect to upstream server.
    #[error("Failed to connect to upstream '{addr}': {message}")]
    UpstreamConnect {
        /// The address we tried to connect to.
        addr: String,
        /// Error message.
        message: String,
    },

    /// Upgrade to tunnel failed.
    #[error("HTTP upgrade failed: {0}")]
    UpgradeFailed(String),

    /// Channel communication error.
    #[error("Channel error: {0}")]
    Channel(String),

    /// Server shutdown requested.
    #[error("Server shutdown")]
    Shutdown,
}

/// Result type for proxy operations.
pub type ProxyResult<T> = Result<T, ProxyError>;

impl From<rustls::Error> for ProxyError {
    fn from(err: rustls::Error) -> Self {
        ProxyError::Tls(err.to_string())
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for ProxyError {
    fn from(err: tokio::sync::oneshot::error::RecvError) -> Self {
        ProxyError::Channel(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_error_display() {
        let err = ProxyError::InvalidConnect("missing authority".to_string());
        assert!(err.to_string().contains("missing authority"));
    }

    #[test]
    fn test_upstream_connect_error() {
        let err = ProxyError::UpstreamConnect {
            addr: "api.example.com:443".to_string(),
            message: "connection refused".to_string(),
        };
        assert!(err.to_string().contains("api.example.com:443"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn test_tls_error() {
        let err = ProxyError::Tls("handshake failed".to_string());
        assert!(err.to_string().contains("handshake failed"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let proxy_err: ProxyError = io_err.into();
        assert!(matches!(proxy_err, ProxyError::Io(_)));
    }
}
