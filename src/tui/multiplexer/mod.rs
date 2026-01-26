//! Terminal multiplexer abstraction layer.
//!
//! This module provides a unified interface for terminal multiplexers (tmux, zellij)
//! to create sidecar panes for the TUI.
//!
//! # Detection Priority
//!
//! When both multiplexers are detected (e.g., running zellij inside tmux):
//! 1. **Zellij** is preferred - users running zellij inside tmux typically want zellij behavior
//! 2. Falls back to Tmux if only TMUX env var is present
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::tui::multiplexer::{create_multiplexer, SidecarOptions};
//!
//! if let Some(mux) = create_multiplexer() {
//!     let options = SidecarOptions {
//!         height: Some(15),
//!         command: Some("my-tui-command".to_string()),
//!         focus: false,
//!     };
//!     let pane = mux.create_sidecar_pane(options)?;
//!     // pane will be cleaned up on drop
//! }
//! ```

pub mod tmux;
pub mod zellij;

use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

// Re-export implementations
pub use tmux::TmuxMultiplexer;
pub use zellij::ZellijMultiplexer;

/// Errors from multiplexer operations.
#[derive(Debug, Error)]
pub enum MultiplexerError {
    /// Failed to execute multiplexer command.
    #[error("Failed to execute command: {0}")]
    ExecutionFailed(#[from] std::io::Error),
    /// Multiplexer command returned non-zero exit code.
    #[error("Command failed: {0}")]
    CommandFailed(String),
    /// Not running inside any supported multiplexer.
    #[error("Not running inside a terminal multiplexer")]
    NotInMultiplexer,
    /// Multiplexer-specific error.
    #[error("{multiplexer} error: {message}")]
    MultiplexerSpecific {
        /// The type of multiplexer that encountered the error.
        multiplexer: MultiplexerKind,
        /// The error message.
        message: String,
    },
}

/// Result type for multiplexer operations.
pub type MultiplexerResult<T> = Result<T, MultiplexerError>;

/// Supported terminal multiplexers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiplexerKind {
    /// tmux - terminal multiplexer
    Tmux,
    /// Zellij - modern terminal multiplexer
    Zellij,
}

impl std::fmt::Display for MultiplexerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultiplexerKind::Tmux => write!(f, "tmux"),
            MultiplexerKind::Zellij => write!(f, "zellij"),
        }
    }
}

/// Options for creating a sidecar pane.
#[derive(Debug, Clone)]
pub struct SidecarOptions {
    /// Height of the pane in lines. If `None`, uses multiplexer default.
    pub height: Option<u32>,
    /// Command to run in the pane. If `None`, starts a shell.
    pub command: Option<String>,
    /// Whether to focus the new pane after creation.
    pub focus: bool,
}

impl Default for SidecarOptions {
    fn default() -> Self {
        Self {
            height: Some(15),
            command: None,
            focus: false,
        }
    }
}

/// Handle to a sidecar pane that can send commands and clean up.
pub trait SidecarPaneHandle: Send + Sync {
    /// Get the pane identifier (format depends on multiplexer).
    fn pane_id(&self) -> &str;

    /// Send keys/text to the pane.
    fn send_keys(&self, keys: &str) -> MultiplexerResult<()>;

    /// Kill/close the pane.
    fn kill(&self) -> MultiplexerResult<()>;

    /// Get the multiplexer kind this pane belongs to.
    fn multiplexer_kind(&self) -> MultiplexerKind;
}

/// Terminal multiplexer interface.
pub trait TerminalMultiplexer: Send + Sync {
    /// Get the kind of multiplexer.
    fn kind(&self) -> MultiplexerKind;

    /// Check if this multiplexer is currently active (we're running inside it).
    fn is_active(&self) -> bool;

    /// Get the current session name, if available.
    fn session_name(&self) -> Option<String>;

    /// Create a sidecar pane with the given options.
    fn create_sidecar_pane(
        &self,
        options: SidecarOptions,
    ) -> MultiplexerResult<Box<dyn SidecarPaneHandle>>;
}

/// Default height for TUI sidecar panes (in lines).
pub const DEFAULT_SIDECAR_HEIGHT: u32 = 15;

/// Check if running inside Zellij.
#[must_use]
pub fn is_in_zellij() -> bool {
    std::env::var("ZELLIJ").is_ok()
}

/// Check if running inside tmux.
#[must_use]
pub fn is_in_tmux() -> bool {
    std::env::var("TMUX").is_ok()
}

/// Check if running inside any supported terminal multiplexer.
#[must_use]
pub fn is_in_multiplexer() -> bool {
    is_in_zellij() || is_in_tmux()
}

/// Detect which multiplexer is active.
///
/// Returns `Some(kind)` if running inside a supported multiplexer, `None` otherwise.
/// If both Zellij and tmux are detected, Zellij takes priority.
#[must_use]
pub fn detect_multiplexer() -> Option<MultiplexerKind> {
    // Zellij takes priority (user running zellij inside tmux wants zellij behavior)
    if is_in_zellij() {
        debug!("Detected Zellij multiplexer");
        return Some(MultiplexerKind::Zellij);
    }

    if is_in_tmux() {
        debug!("Detected tmux multiplexer");
        return Some(MultiplexerKind::Tmux);
    }

    debug!("No terminal multiplexer detected");
    None
}

/// Create a multiplexer instance for the detected environment.
///
/// Returns `Some(multiplexer)` if running inside a supported multiplexer,
/// `None` if not in any multiplexer.
#[must_use]
pub fn create_multiplexer() -> Option<Arc<dyn TerminalMultiplexer>> {
    match detect_multiplexer() {
        Some(MultiplexerKind::Zellij) => {
            info!("Using Zellij multiplexer");
            Some(Arc::new(ZellijMultiplexer::new()))
        }
        Some(MultiplexerKind::Tmux) => {
            info!("Using tmux multiplexer");
            Some(Arc::new(TmuxMultiplexer::new()))
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiplexer_kind_display() {
        assert_eq!(format!("{}", MultiplexerKind::Tmux), "tmux");
        assert_eq!(format!("{}", MultiplexerKind::Zellij), "zellij");
    }

    #[test]
    fn test_sidecar_options_default() {
        let opts = SidecarOptions::default();
        assert_eq!(opts.height, Some(15));
        assert!(opts.command.is_none());
        assert!(!opts.focus);
    }

    #[test]
    fn test_detection_functions_no_panic() {
        // These tests just verify the functions don't panic
        let _ = is_in_zellij();
        let _ = is_in_tmux();
        let _ = is_in_multiplexer();
        let _ = detect_multiplexer();
    }

    #[test]
    fn test_create_multiplexer_no_panic() {
        // This test just verifies the function doesn't panic
        let _ = create_multiplexer();
    }
}
