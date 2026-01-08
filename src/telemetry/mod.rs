//! Telemetry and audit logging for secure-llm.
//!
//! This module provides structured logging to syslog with the `AGENTIC_SANDBOX` tag.
//! All security-relevant events are logged for SIEM integration and audit trails.
//!
//! # Architecture
//!
//! - **Audit logging** (syslog): Security events go to syslog, never stdout/stderr
//! - **Debug logging** (tracing): Development logs go to stderr via `tracing`
//! - These are completely separate concerns
//!
//! # Usage
//!
//! ```ignore
//! use secure_llm::telemetry::{self, AuditEvent};
//!
//! // Initialize at startup
//! telemetry::init_logger()?;
//!
//! // Log events throughout the application
//! telemetry::audit().log(AuditEvent::SessionStart {
//!     user: "developer".to_string(),
//!     tool: "claude".to_string(),
//!     pid: std::process::id(),
//! });
//! ```
//!
//! # Event Format
//!
//! Events are logged as JSON with an ISO8601 timestamp:
//!
//! ```json
//! {"ts":"2026-01-07T14:32:01Z","event":"session_start","user":"developer","tool":"claude","pid":12345}
//! ```

mod error;
mod events;
mod syslog;

pub use error::TelemetryError;
pub use events::{AllowReason, AuditEvent, BlockReason, Decision};
pub use syslog::{audit, init_logger, try_audit, AuditLogger, SYSLOG_TAG};
