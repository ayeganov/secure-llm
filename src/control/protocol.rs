//! IPC protocol message types for control plane communication.
//!
//! This module defines the message types exchanged between:
//! - Proxy/PortMon -> TUI (permission requests, port detection, logs)
//! - TUI -> Proxy (permission decisions, port forwarding decisions)
//!
//! # Message Flow
//!
//! ```text
//! ┌─────────────────┐     ProxyToTui      ┌─────────────────┐
//! │                 │────────────────────>│                 │
//! │  Proxy/PortMon  │                     │       TUI       │
//! │                 │<────────────────────│                 │
//! └─────────────────┘     TuiToProxy      └─────────────────┘
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Log level for log events sent to TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    /// Debug-level message.
    Debug,
    /// Informational message.
    Info,
    /// Warning message.
    Warn,
    /// Error message.
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// Category of log event for filtering/display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventCategory {
    /// Network/proxy related event.
    Network,
    /// Sandbox related event.
    Sandbox,
    /// Port detection event.
    Port,
    /// Policy evaluation event.
    Policy,
    /// System/general event.
    System,
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventCategory::Network => write!(f, "NET"),
            EventCategory::Sandbox => write!(f, "SANDBOX"),
            EventCategory::Port => write!(f, "PORT"),
            EventCategory::Policy => write!(f, "POLICY"),
            EventCategory::System => write!(f, "SYSTEM"),
        }
    }
}

/// User decision for permission prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Allow the connection.
    Allow,
    /// Block the connection.
    Block,
}

/// Messages sent from Proxy/PortMon to TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyToTui {
    /// A new domain requires permission.
    PermissionRequest {
        /// Unique identifier for this request.
        id: Uuid,
        /// The domain being accessed.
        domain: String,
        /// The port being accessed.
        port: u16,
        /// When the request was created.
        timestamp: DateTime<Utc>,
    },
    /// A new port was detected listening in the sandbox.
    PortDetected {
        /// Unique identifier for this detection.
        id: Uuid,
        /// The port number.
        port: u16,
        /// The local address (e.g., "0.0.0.0", "127.0.0.1", "::").
        local_addr: String,
        /// Process name if identifiable.
        process_name: Option<String>,
        /// When the port was detected.
        timestamp: DateTime<Utc>,
    },
    /// A log event for display in TUI.
    LogEvent {
        /// Log level.
        level: LogLevel,
        /// Event category.
        category: EventCategory,
        /// The log message.
        message: String,
        /// When the event occurred.
        timestamp: DateTime<Utc>,
    },
    /// A permission request was cancelled (timeout, client disconnect, etc.).
    PermissionCancelled {
        /// The ID of the cancelled request.
        id: Uuid,
        /// Reason for cancellation.
        reason: String,
    },
    /// A port bridge was successfully started.
    PortBridgeStarted {
        /// The ID of the original port detection.
        id: Uuid,
        /// The host port being listened on.
        host_port: u16,
        /// The container port being forwarded to.
        container_port: u16,
    },
    /// A port bridge was stopped.
    PortBridgeStopped {
        /// The host port that was being listened on.
        host_port: u16,
        /// The container port that was being forwarded to.
        container_port: u16,
        /// Reason for stopping (e.g., "app closed", "manual", "error").
        reason: String,
    },
    /// A port that was being monitored has closed.
    PortClosed {
        /// The ID of the port detection.
        id: Uuid,
        /// The port number.
        port: u16,
    },
    /// Signal that the proxy is shutting down.
    Shutdown,
}

/// Messages sent from TUI to Proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TuiToProxy {
    /// User made a decision on a permission request.
    PermissionDecision {
        /// The ID of the permission request.
        id: Uuid,
        /// The decision (Allow or Block).
        decision: Decision,
        /// Whether to persist this decision (Always Allow/Block).
        persist: bool,
    },
    /// User made a decision on port forwarding.
    PortDecision {
        /// The ID of the port detection.
        id: Uuid,
        /// Whether to bridge this port.
        bridge: bool,
        /// The host port to forward to (if bridging).
        host_port: Option<u16>,
    },
    /// User requested to stop a port bridge.
    StopBridge {
        /// The ID of the port detection.
        id: Uuid,
    },
    /// TUI is shutting down.
    TuiShutdown,
}

/// A pending permission request (for TUI display).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPermission {
    /// Unique identifier.
    pub id: Uuid,
    /// Target domain.
    pub domain: String,
    /// Target port.
    pub port: u16,
    /// Seconds waiting for decision.
    pub waiting_secs: u64,
    /// When the request was created.
    pub timestamp: DateTime<Utc>,
}

/// A detected port (for TUI display).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPort {
    /// Unique identifier.
    pub id: Uuid,
    /// The port number.
    pub port: u16,
    /// The local address.
    pub local_addr: String,
    /// Process name if known.
    pub process_name: Option<String>,
    /// Whether this port is being forwarded.
    pub forwarded: bool,
    /// When the port was detected.
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_display() {
        assert_eq!(format!("{}", LogLevel::Debug), "DEBUG");
        assert_eq!(format!("{}", LogLevel::Info), "INFO");
        assert_eq!(format!("{}", LogLevel::Warn), "WARN");
        assert_eq!(format!("{}", LogLevel::Error), "ERROR");
    }

    #[test]
    fn test_event_category_display() {
        assert_eq!(format!("{}", EventCategory::Network), "NET");
        assert_eq!(format!("{}", EventCategory::Sandbox), "SANDBOX");
        assert_eq!(format!("{}", EventCategory::Port), "PORT");
    }

    #[test]
    fn test_proxy_to_tui_permission_request() {
        let msg = ProxyToTui::PermissionRequest {
            id: Uuid::new_v4(),
            domain: "api.example.com".to_string(),
            port: 443,
            timestamp: Utc::now(),
        };

        match msg {
            ProxyToTui::PermissionRequest { domain, port, .. } => {
                assert_eq!(domain, "api.example.com");
                assert_eq!(port, 443);
            }
            _ => unreachable!("Expected PermissionRequest"),
        }
    }

    #[test]
    fn test_tui_to_proxy_decision() {
        let msg = TuiToProxy::PermissionDecision {
            id: Uuid::new_v4(),
            decision: Decision::Allow,
            persist: true,
        };

        match msg {
            TuiToProxy::PermissionDecision { decision, persist, .. } => {
                assert_eq!(decision, Decision::Allow);
                assert!(persist);
            }
            _ => unreachable!("Expected PermissionDecision"),
        }
    }
}
