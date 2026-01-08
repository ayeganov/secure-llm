//! Telemetry error types.

use thiserror::Error;

/// Errors that can occur during telemetry operations.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// Failed to connect to syslog.
    #[error("Failed to connect to syslog: {0}")]
    SyslogConnection(String),

    /// Failed to send log message.
    #[error("Failed to send log message: {0}")]
    SendError(String),

    /// Failed to serialize event to JSON.
    #[error("Failed to serialize event: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Logger not initialized.
    #[error("Audit logger not initialized - call init_logger() first")]
    NotInitialized,

    /// Logger already initialized.
    #[error("Audit logger already initialized")]
    AlreadyInitialized,
}
