//! Audit event types for structured logging.
//!
//! These events are logged to syslog with the `AGENTIC_SANDBOX` tag
//! for SIEM integration and security audit trails.

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Audit events for security logging.
///
/// Each variant represents a significant security-relevant event that
/// is logged to syslog for audit purposes.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Session started - sandbox launched.
    SessionStart {
        /// Username of the person running the sandbox.
        user: String,
        /// Tool being sandboxed (claude, cursor, etc.).
        tool: String,
        /// Process ID of the sandbox orchestrator.
        pid: u32,
    },

    /// Session ended - sandbox terminated.
    SessionEnd {
        /// Username of the person who ran the sandbox.
        user: String,
        /// Tool that was sandboxed.
        tool: String,
        /// Duration of the session in seconds.
        duration_sec: u64,
    },

    /// Network access allowed.
    NetworkAllow {
        /// Domain that was allowed.
        domain: String,
        /// Reason for allowing.
        reason: AllowReason,
    },

    /// Network access blocked.
    NetworkBlock {
        /// Domain that was blocked.
        domain: String,
        /// Reason for blocking.
        reason: BlockReason,
    },

    /// Network access required user prompt.
    NetworkPrompt {
        /// Domain that was prompted for.
        domain: String,
        /// User's decision.
        decision: Decision,
        /// Whether the decision was persisted to allowlist.
        persist: bool,
    },

    /// Mount access denied due to sensitive source.
    MountDeny {
        /// Path that was requested.
        path: String,
        /// Mount source that triggered denial.
        source: String,
        /// Reason for denial.
        reason: String,
    },

    /// New listening port detected in sandbox.
    PortDetect {
        /// Port number.
        port: u16,
        /// Process name (if identifiable).
        process: Option<String>,
    },

    /// Port bridged from sandbox to host.
    PortBridge {
        /// Port inside the sandbox.
        container_port: u16,
        /// Port on the host.
        host_port: u16,
    },
}

/// Reasons for allowing network access.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowReason {
    /// Matched base allowlist (system/embedded config).
    BaseAllowlist,
    /// Matched user's persistent allowlist.
    UserAllowlist,
    /// User allowed for this session only.
    SessionAllow,
    /// Pre-allowed via CLI flag.
    CliFlag,
}

/// Reasons for blocking network access.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// Matched blocklist.
    Blocklist,
    /// Permission prompt timed out (fail-closed).
    PromptTimeout,
    /// User explicitly denied.
    UserDenied,
    /// Matched graylist and user denied.
    GraylistDenied,
}

/// User decision for permission prompts.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Access allowed.
    Allow,
    /// Access blocked.
    Block,
}

/// Wrapper for serializing events with timestamp.
#[derive(Debug, Clone, Serialize)]
pub struct TimestampedEvent<'a> {
    /// ISO8601 timestamp.
    #[serde(rename = "ts")]
    pub timestamp: DateTime<Utc>,

    /// The actual event (flattened into this struct).
    #[serde(flatten)]
    pub event: &'a AuditEvent,
}

impl AuditEvent {
    /// Wrap this event with a timestamp for serialization.
    pub fn with_timestamp(&self) -> TimestampedEvent<'_> {
        TimestampedEvent {
            timestamp: Utc::now(),
            event: self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_start_serialization() {
        let event = AuditEvent::SessionStart {
            user: "developer".to_string(),
            tool: "claude".to_string(),
            pid: 12345,
        };

        let timestamped = event.with_timestamp();
        let json = serde_json::to_string(&timestamped).unwrap();

        assert!(json.contains("\"event\":\"session_start\""));
        assert!(json.contains("\"user\":\"developer\""));
        assert!(json.contains("\"tool\":\"claude\""));
        assert!(json.contains("\"pid\":12345"));
        assert!(json.contains("\"ts\""));
    }

    #[test]
    fn test_network_allow_serialization() {
        let event = AuditEvent::NetworkAllow {
            domain: "pypi.org".to_string(),
            reason: AllowReason::BaseAllowlist,
        };

        let timestamped = event.with_timestamp();
        let json = serde_json::to_string(&timestamped).unwrap();

        assert!(json.contains("\"event\":\"network_allow\""));
        assert!(json.contains("\"domain\":\"pypi.org\""));
        assert!(json.contains("\"reason\":\"base_allowlist\""));
    }

    #[test]
    fn test_network_block_serialization() {
        let event = AuditEvent::NetworkBlock {
            domain: "evil.io".to_string(),
            reason: BlockReason::Blocklist,
        };

        let timestamped = event.with_timestamp();
        let json = serde_json::to_string(&timestamped).unwrap();

        assert!(json.contains("\"event\":\"network_block\""));
        assert!(json.contains("\"reason\":\"blocklist\""));
    }

    #[test]
    fn test_network_prompt_serialization() {
        let event = AuditEvent::NetworkPrompt {
            domain: "api.unknown.com".to_string(),
            decision: Decision::Allow,
            persist: false,
        };

        let timestamped = event.with_timestamp();
        let json = serde_json::to_string(&timestamped).unwrap();

        assert!(json.contains("\"event\":\"network_prompt\""));
        assert!(json.contains("\"decision\":\"allow\""));
        assert!(json.contains("\"persist\":false"));
    }

    #[test]
    fn test_mount_deny_serialization() {
        let event = AuditEvent::MountDeny {
            path: "/mnt/secure/data".to_string(),
            source: "10.1.2.3:/secure-exports".to_string(),
            reason: "denylist".to_string(),
        };

        let timestamped = event.with_timestamp();
        let json = serde_json::to_string(&timestamped).unwrap();

        assert!(json.contains("\"event\":\"mount_deny\""));
        assert!(json.contains("\"source\":\"10.1.2.3:/secure-exports\""));
    }

    #[test]
    fn test_port_detect_serialization() {
        let event = AuditEvent::PortDetect {
            port: 3000,
            process: Some("node".to_string()),
        };

        let timestamped = event.with_timestamp();
        let json = serde_json::to_string(&timestamped).unwrap();

        assert!(json.contains("\"event\":\"port_detect\""));
        assert!(json.contains("\"port\":3000"));
        assert!(json.contains("\"process\":\"node\""));
    }

    #[test]
    fn test_port_bridge_serialization() {
        let event = AuditEvent::PortBridge {
            container_port: 3000,
            host_port: 3000,
        };

        let timestamped = event.with_timestamp();
        let json = serde_json::to_string(&timestamped).unwrap();

        assert!(json.contains("\"event\":\"port_bridge\""));
        assert!(json.contains("\"container_port\":3000"));
        assert!(json.contains("\"host_port\":3000"));
    }

    #[test]
    fn test_session_end_serialization() {
        let event = AuditEvent::SessionEnd {
            user: "developer".to_string(),
            tool: "claude".to_string(),
            duration_sec: 179,
        };

        let timestamped = event.with_timestamp();
        let json = serde_json::to_string(&timestamped).unwrap();

        assert!(json.contains("\"event\":\"session_end\""));
        assert!(json.contains("\"duration_sec\":179"));
    }
}
