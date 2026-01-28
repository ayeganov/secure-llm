//! Terminal user interface module.
//!
//! This module provides a ratatui-based TUI for:
//! - Pending permission prompts display
//! - Detected ports management
//! - Live log stream
//! - Status bar with sandbox info
//! - Keyboard input handling for permission decisions
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────┬────────────────────┐
//! │                    │                    │
//! │   Permissions      │      Ports         │
//! │   [a]llow          │   [p] bridge       │
//! │   [b]lock          │                    │
//! │   [A]lways allow   │                    │
//! │   [B]lways block   │                    │
//! │                    │                    │
//! ├────────────────────┴────────────────────┤
//! │                                         │
//! │                 Logs                    │
//! │   Real-time log stream from proxy      │
//! │                                         │
//! ├─────────────────────────────────────────┤
//! │ [Tab] switch | [j/k] navigate | [q] quit│
//! └─────────────────────────────────────────┘
//! ```

pub mod app;
pub mod input;
pub mod layout;
pub mod multiplexer;
pub mod runner;
pub mod state;
pub mod transport;
pub mod widgets;

// Re-export main types for convenient access
pub use app::TuiApp;
pub use input::{handle_event, InputResult};
pub use layout::TuiLayout;
pub use runner::{run_with_recovery, TuiRunner};
pub use state::{FocusPanel, LogEntry, MAX_LOG_ENTRIES};
pub use widgets::{LogsWidget, PendingWidget, PortsWidget, StatusWidget};

// Re-export multiplexer types for convenient access
pub use multiplexer::{
    create_multiplexer, detect_multiplexer, is_in_multiplexer, is_in_tmux, is_in_zellij,
    MultiplexerError, MultiplexerKind, MultiplexerResult, SidecarOptions, SidecarPaneHandle,
    TerminalMultiplexer, TmuxMultiplexer, ZellijMultiplexer, DEFAULT_SIDECAR_HEIGHT,
};
