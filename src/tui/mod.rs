//! Terminal user interface module (Phase 4).
//!
//! This module will provide a ratatui-based TUI for:
//! - Pending permission prompts display
//! - Live log stream
//! - Status bar with sandbox info
//! - Keyboard input handling for permission decisions
//!
//! The TUI runs in a separate tmux pane (sidecar) from the wrapped tool.

// Phase 4 submodules (to be implemented):
// pub mod app;        // ratatui application state
// pub mod layout;     // Pane layout definitions
// pub mod widgets;    // Custom widgets
// pub mod input;      // Keyboard event handling

/// Placeholder for TUI functionality.
///
/// This will be implemented in Phase 4.
pub struct Tui;

impl Tui {
    /// Create a new TUI (not yet implemented).
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for Tui {
    fn default() -> Self {
        Self::new()
    }
}
