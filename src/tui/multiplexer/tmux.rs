//! Tmux implementation of the multiplexer abstraction.
//!
//! This module provides tmux-specific functionality for creating sidecar panes.
//!
//! # Tmux Layout
//!
//! ```text
//! +----------------------------------------+
//! |                                        |
//! |         Wrapped Tool (e.g., Claude)    |
//! |                                        |
//! |         (has full terminal access)     |
//! |                                        |
//! +----------------------------------------+
//! |  secure-llm TUI (permission prompts)   |
//! |  [15 lines high]                       |
//! +----------------------------------------+
//! ```

use std::process::Command;
use tracing::{debug, info, warn};

use super::{
    MultiplexerError, MultiplexerKind, MultiplexerResult, SidecarOptions, SidecarPaneHandle,
    TerminalMultiplexer, DEFAULT_SIDECAR_HEIGHT,
};

/// Tmux multiplexer implementation.
#[derive(Debug, Default)]
pub struct TmuxMultiplexer;

impl TmuxMultiplexer {
    /// Create a new tmux multiplexer instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Get the current tmux pane ID from environment.
    #[must_use]
    pub fn current_pane_id() -> Option<String> {
        std::env::var("TMUX_PANE").ok()
    }
}

impl TerminalMultiplexer for TmuxMultiplexer {
    fn kind(&self) -> MultiplexerKind {
        MultiplexerKind::Tmux
    }

    fn is_active(&self) -> bool {
        std::env::var("TMUX").is_ok()
    }

    fn session_name(&self) -> Option<String> {
        if !self.is_active() {
            return None;
        }

        Command::new("tmux")
            .args(["display-message", "-p", "#{session_name}"])
            .output()
            .ok()
            .and_then(|out| {
                if out.status.success() {
                    String::from_utf8(out.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    }

    fn create_sidecar_pane(
        &self,
        options: SidecarOptions,
    ) -> MultiplexerResult<Box<dyn SidecarPaneHandle>> {
        if !self.is_active() {
            return Err(MultiplexerError::NotInMultiplexer);
        }

        let height = options.height.unwrap_or(DEFAULT_SIDECAR_HEIGHT);
        let height_str = height.to_string();

        // Build split-window command
        let mut args = vec![
            "split-window",
            "-v",         // Vertical split (new pane below)
            "-l",         // Specify size
            &height_str,
            "-P",         // Print pane info
            "-F",         // Format string
            "#{pane_id}", // Output just the pane ID
        ];

        // Don't focus the new pane unless requested
        if !options.focus {
            args.insert(2, "-d");
        }

        // Add command if specified
        let cmd_string;
        if let Some(ref cmd) = options.command {
            cmd_string = cmd.clone();
            args.push(&cmd_string);
        }

        debug!("Creating tmux sidecar pane with args: {:?}", args);

        let output = Command::new("tmux").args(&args).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MultiplexerError::CommandFailed(format!(
                "Failed to create sidecar pane: {}",
                stderr
            )));
        }

        let pane_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        info!("Created tmux sidecar pane: {}", pane_id);

        Ok(Box::new(TmuxSidecarPane {
            pane_id,
            killed: false,
        }))
    }
}

/// Handle to a tmux sidecar pane.
#[derive(Debug)]
pub struct TmuxSidecarPane {
    /// The tmux pane ID (e.g., "%5").
    pane_id: String,
    /// Whether the pane has been killed.
    killed: bool,
}

impl SidecarPaneHandle for TmuxSidecarPane {
    fn pane_id(&self) -> &str {
        &self.pane_id
    }

    fn send_keys(&self, keys: &str) -> MultiplexerResult<()> {
        let output = Command::new("tmux")
            .args(["send-keys", "-t", &self.pane_id, keys, "Enter"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MultiplexerError::CommandFailed(format!(
                "Failed to send keys: {}",
                stderr
            )));
        }

        Ok(())
    }

    fn focus(&self) -> MultiplexerResult<()> {
        let output = Command::new("tmux")
            .args(["select-pane", "-t", &self.pane_id])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MultiplexerError::CommandFailed(format!(
                "Failed to focus pane: {}",
                stderr
            )));
        }

        debug!("Focused tmux pane {}", self.pane_id);
        Ok(())
    }

    fn kill(&self) -> MultiplexerResult<()> {
        let output = Command::new("tmux")
            .args(["kill-pane", "-t", &self.pane_id])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't fail if pane is already gone
            if !stderr.contains("not found") && !stderr.contains("no such") {
                return Err(MultiplexerError::CommandFailed(format!(
                    "Failed to kill pane: {}",
                    stderr
                )));
            }
        }

        debug!("Killed tmux sidecar pane {}", self.pane_id);
        Ok(())
    }

    fn multiplexer_kind(&self) -> MultiplexerKind {
        MultiplexerKind::Tmux
    }
}

impl Drop for TmuxSidecarPane {
    fn drop(&mut self) {
        if !self.killed {
            if let Err(e) = self.kill() {
                warn!("Failed to cleanup tmux sidecar pane: {}", e);
            }
            self.killed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tmux_multiplexer_kind() {
        let mux = TmuxMultiplexer::new();
        assert_eq!(mux.kind(), MultiplexerKind::Tmux);
    }

    #[test]
    fn test_is_active_no_panic() {
        let mux = TmuxMultiplexer::new();
        let _ = mux.is_active();
    }

    #[test]
    fn test_session_name_no_panic() {
        let mux = TmuxMultiplexer::new();
        let _ = mux.session_name();
    }

    #[test]
    fn test_current_pane_id_no_panic() {
        let _ = TmuxMultiplexer::current_pane_id();
    }

    #[test]
    fn test_create_sidecar_not_in_tmux() {
        // Skip if actually in tmux
        if std::env::var("TMUX").is_ok() {
            return;
        }

        let mux = TmuxMultiplexer::new();
        let result = mux.create_sidecar_pane(SidecarOptions::default());
        assert!(matches!(result, Err(MultiplexerError::NotInMultiplexer)));
    }
}
