//! TUI application state definitions.

use crate::control::protocol::{EventCategory, LogLevel};
use chrono::{DateTime, Utc};

/// Maximum number of log entries to keep in memory.
pub const MAX_LOG_ENTRIES: usize = 1000;

/// Maximum number of detected ports to track.
pub const MAX_DETECTED_PORTS: usize = 100;

/// Which panel has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FocusPanel {
    /// Permission requests panel.
    #[default]
    Permissions,
    /// Detected ports panel.
    Ports,
    /// Log messages panel.
    Logs,
}

impl FocusPanel {
    /// Cycle to the next panel.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            FocusPanel::Permissions => FocusPanel::Ports,
            FocusPanel::Ports => FocusPanel::Logs,
            FocusPanel::Logs => FocusPanel::Permissions,
        }
    }

    /// Cycle to the previous panel.
    #[must_use]
    pub fn prev(self) -> Self {
        match self {
            FocusPanel::Permissions => FocusPanel::Logs,
            FocusPanel::Ports => FocusPanel::Permissions,
            FocusPanel::Logs => FocusPanel::Ports,
        }
    }
}

/// A log entry for display.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Log level.
    pub level: LogLevel,
    /// Event category.
    pub category: EventCategory,
    /// The log message.
    pub message: String,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
}
