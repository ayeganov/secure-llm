//! Syslog integration for audit logging.
//!
//! All audit events are logged to syslog with the `AGENTIC_SANDBOX` tag
//! for SIEM integration and security audit trails.

use std::sync::{Mutex, OnceLock};

use syslog::{Facility, Formatter3164};
use tracing::{debug, error};

use super::error::TelemetryError;
use super::events::AuditEvent;

/// Syslog tag for all audit events.
pub const SYSLOG_TAG: &str = "AGENTIC_SANDBOX";

/// Global audit logger instance.
static AUDIT_LOGGER: OnceLock<AuditLogger> = OnceLock::new();

/// Audit logger that writes structured JSON events to syslog.
///
/// Uses interior mutability (Mutex) to allow logging from shared references,
/// which is necessary since the logger is stored in a global OnceLock.
pub struct AuditLogger {
    /// Syslog writer protected by a mutex for interior mutability.
    /// None indicates a null logger (for testing).
    writer: Option<Mutex<syslog::Logger<syslog::LoggerBackend, Formatter3164>>>,
}

impl AuditLogger {
    /// Create a new audit logger connected to syslog.
    ///
    /// Uses Unix socket connection to local syslog daemon.
    pub fn new() -> Result<Self, TelemetryError> {
        let formatter = Formatter3164 {
            facility: Facility::LOG_USER,
            hostname: None,
            process: SYSLOG_TAG.to_string(),
            pid: std::process::id(),
        };

        let writer = syslog::unix(formatter).map_err(|e| {
            TelemetryError::SyslogConnection(format!("Failed to connect to syslog: {}", e))
        })?;

        debug!("Connected to syslog with tag '{}'", SYSLOG_TAG);
        Ok(Self {
            writer: Some(Mutex::new(writer)),
        })
    }

    /// Create a null audit logger that discards all events.
    ///
    /// Useful for testing when syslog is not available.
    pub fn new_null() -> Self {
        Self { writer: None }
    }

    /// Log an audit event to syslog.
    ///
    /// The event is serialized to JSON with an ISO8601 timestamp.
    /// If this is a null logger, the event is silently discarded.
    pub fn log(&self, event: AuditEvent) {
        let Some(ref writer) = self.writer else {
            // Null logger - discard silently
            return;
        };

        let timestamped = event.with_timestamp();

        match serde_json::to_string(&timestamped) {
            Ok(json) => {
                // Log at INFO level to syslog
                match writer.lock() {
                    Ok(mut writer) => {
                        if let Err(e) = writer.info(&json) {
                            error!("Failed to write to syslog: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to acquire syslog writer lock: {}", e);
                    }
                }
                debug!("Logged audit event: {}", json);
            }
            Err(e) => {
                error!("Failed to serialize audit event: {}", e);
            }
        }
    }

    /// Log an audit event with additional context.
    ///
    /// The context is appended to the JSON as an additional field.
    /// If this is a null logger, the event is silently discarded.
    pub fn log_with_context(&self, event: AuditEvent, context: &str) {
        let Some(ref writer) = self.writer else {
            // Null logger - discard silently
            return;
        };

        let timestamped = event.with_timestamp();

        // Create a combined structure with context
        #[derive(serde::Serialize)]
        struct WithContext<'a, T> {
            #[serde(flatten)]
            inner: T,
            context: &'a str,
        }

        let with_context = WithContext {
            inner: timestamped,
            context,
        };

        match serde_json::to_string(&with_context) {
            Ok(json) => {
                match writer.lock() {
                    Ok(mut writer) => {
                        if let Err(e) = writer.info(&json) {
                            error!("Failed to write to syslog: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to acquire syslog writer lock: {}", e);
                    }
                }
                debug!("Logged audit event with context: {}", json);
            }
            Err(e) => {
                error!("Failed to serialize audit event: {}", e);
            }
        }
    }

    /// Check if this is a null logger.
    pub fn is_null(&self) -> bool {
        self.writer.is_none()
    }
}

/// Initialize the global audit logger.
///
/// This must be called once at startup before any audit logging.
/// Returns an error if syslog connection fails or if already initialized.
pub fn init_logger() -> Result<(), TelemetryError> {
    let logger = AuditLogger::new()?;

    AUDIT_LOGGER
        .set(logger)
        .map_err(|_| TelemetryError::AlreadyInitialized)?;

    Ok(())
}

/// Get a reference to the global audit logger.
///
/// # Panics
///
/// Panics if `init_logger()` was not called first.
pub fn audit() -> &'static AuditLogger {
    AUDIT_LOGGER
        .get()
        .expect("Audit logger not initialized - call init_logger() first")
}

/// Try to get a reference to the global audit logger.
///
/// Returns None if `init_logger()` was not called.
pub fn try_audit() -> Option<&'static AuditLogger> {
    AUDIT_LOGGER.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running syslog daemon.
    // In CI environments, they may be skipped or require special setup.

    #[test]
    fn test_syslog_tag() {
        assert_eq!(SYSLOG_TAG, "AGENTIC_SANDBOX");
    }

    // Integration test - requires syslog daemon
    #[test]
    #[ignore = "Requires running syslog daemon"]
    fn test_logger_creation() {
        let logger = AuditLogger::new();
        assert!(logger.is_ok());
    }

    // Integration test - requires syslog daemon
    #[test]
    #[ignore = "Requires running syslog daemon"]
    fn test_log_event() {
        let logger = AuditLogger::new().unwrap();

        let event = AuditEvent::SessionStart {
            user: "test_user".to_string(),
            tool: "test_tool".to_string(),
            pid: 12345,
        };

        // Should not panic
        logger.log(event);
    }
}
