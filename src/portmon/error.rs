//! Error types for port monitoring operations.
//!
//! This module defines errors for:
//! - Port scanning (reading /proc/net/tcp)
//! - Port forwarding (binding, connecting)
//! - Parse errors

use std::net::SocketAddr;
use thiserror::Error;

/// Errors from port monitoring operations.
#[derive(Debug, Error)]
pub enum PortMonError {
    /// Failed to scan for ports.
    #[error("Failed to scan ports: {0}")]
    ScanFailed(String),

    /// Failed to parse port information.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Failed to listen on a port.
    #[error("Failed to listen on port {port}: {source}")]
    ListenFailed {
        /// The port we tried to listen on.
        port: u16,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to connect to a port.
    #[error("Failed to connect to {addr}: {source}")]
    ConnectFailed {
        /// The address we tried to connect to.
        addr: SocketAddr,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Error during data forwarding.
    #[error("Forward error: {0}")]
    ForwardError(#[source] std::io::Error),

    /// Port is already being forwarded.
    #[error("Port {0} is already being forwarded")]
    PortAlreadyForwarded(u16),

    /// Generic I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for port monitoring operations.
pub type PortMonResult<T> = Result<T, PortMonError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_failed_error() {
        let err = PortMonError::ScanFailed("permission denied".to_string());
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    fn test_parse_error() {
        let err = PortMonError::ParseError("invalid hex".to_string());
        assert!(err.to_string().contains("invalid hex"));
    }

    #[test]
    fn test_listen_failed_error() {
        let err = PortMonError::ListenFailed {
            port: 8080,
            source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "address in use"),
        };
        assert!(err.to_string().contains("8080"));
    }

    #[test]
    fn test_port_already_forwarded() {
        let err = PortMonError::PortAlreadyForwarded(3000);
        assert!(err.to_string().contains("3000"));
    }
}
