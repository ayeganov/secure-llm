//! TUI widgets for rendering panels.
//!
//! This module provides custom widgets for the TUI:
//! - `PendingWidget` - Displays pending permission requests
//! - `LogsWidget` - Displays log messages
//! - `StatusWidget` - Displays status bar with keybindings

pub mod logs;
pub mod pending;
pub mod ports;
pub mod status;

pub use logs::LogsWidget;
pub use pending::PendingWidget;
pub use ports::PortsWidget;
pub use status::StatusWidget;
