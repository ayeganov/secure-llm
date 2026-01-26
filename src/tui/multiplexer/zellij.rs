//! Zellij implementation of the multiplexer abstraction.
//!
//! This module provides zellij-specific functionality for creating sidecar panes.
//!
//! # Zellij Layout
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
//! |  [sidecar pane below]                  |
//! +----------------------------------------+
//! ```
//!
//! # Key Differences from Tmux
//!
//! - Zellij doesn't return pane ID from new-pane (we generate a UUID for tracking)
//! - Focus management uses `zellij action move-focus`
//! - Pane cleanup uses `zellij action close-pane`
//! - Size can be specified with `--size` flag (percentage-based)

use std::process::Command;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{
    MultiplexerError, MultiplexerKind, MultiplexerResult, SidecarOptions, SidecarPaneHandle,
    TerminalMultiplexer, DEFAULT_SIDECAR_HEIGHT,
};

/// Zellij multiplexer implementation.
#[derive(Debug, Default)]
pub struct ZellijMultiplexer;

impl ZellijMultiplexer {
    /// Create a new Zellij multiplexer instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Convert line height to approximate percentage.
    ///
    /// This is a rough conversion since we don't know the actual terminal height.
    /// Assumes a typical terminal of ~40 lines, so 15 lines ≈ 37%.
    fn lines_to_percent(lines: u32) -> u32 {
        // Clamp to reasonable range (10-50%)
        let percent = (lines * 100) / 40;
        percent.clamp(10, 50)
    }

    /// Check if zellij supports the --size flag.
    ///
    /// Older versions of zellij don't have this flag.
    fn supports_size_flag() -> bool {
        // Try running `zellij action new-pane --help` and check for --size
        Command::new("zellij")
            .args(["action", "new-pane", "--help"])
            .output()
            .map(|out| {
                let help_text = String::from_utf8_lossy(&out.stdout);
                help_text.contains("--size")
            })
            .unwrap_or(false)
    }
}

impl TerminalMultiplexer for ZellijMultiplexer {
    fn kind(&self) -> MultiplexerKind {
        MultiplexerKind::Zellij
    }

    fn is_active(&self) -> bool {
        std::env::var("ZELLIJ").is_ok()
    }

    fn session_name(&self) -> Option<String> {
        std::env::var("ZELLIJ_SESSION_NAME").ok()
    }

    fn create_sidecar_pane(
        &self,
        options: SidecarOptions,
    ) -> MultiplexerResult<Box<dyn SidecarPaneHandle>> {
        if !self.is_active() {
            return Err(MultiplexerError::NotInMultiplexer);
        }

        // Generate a UUID for tracking since zellij doesn't return pane IDs
        let pane_uuid = Uuid::new_v4().to_string();

        // Build the command arguments
        let mut args = vec!["action", "new-pane", "--direction", "down"];

        // Try to set size if supported
        let height = options.height.unwrap_or(DEFAULT_SIDECAR_HEIGHT);
        let size_percent = Self::lines_to_percent(height);
        let size_str = format!("{}%", size_percent);

        let supports_size = Self::supports_size_flag();
        if supports_size {
            args.push("--size");
            args.push(&size_str);
        } else {
            debug!(
                "Zellij doesn't support --size flag, using default size"
            );
        }

        // Add command if specified
        if let Some(ref cmd) = options.command {
            args.push("--");
            // We need to use sh -c to run the command
            args.push("sh");
            args.push("-c");
            args.push(cmd);
        }

        debug!("Creating zellij sidecar pane with args: {:?}", args);

        let output = Command::new("zellij").args(&args).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MultiplexerError::CommandFailed(format!(
                "Failed to create sidecar pane: {}",
                stderr
            )));
        }

        info!("Created zellij sidecar pane (tracking id: {})", pane_uuid);

        // Return focus to the original pane if requested (default behavior)
        if !options.focus {
            let focus_result = Command::new("zellij")
                .args(["action", "move-focus", "up"])
                .output();

            if let Err(e) = focus_result {
                warn!("Failed to return focus after creating pane: {}", e);
            }
        }

        Ok(Box::new(ZellijSidecarPane {
            tracking_id: pane_uuid,
            killed: false,
        }))
    }
}

/// Handle to a zellij sidecar pane.
#[derive(Debug)]
pub struct ZellijSidecarPane {
    /// Tracking ID for this pane (UUID since zellij doesn't provide pane IDs).
    tracking_id: String,
    /// Whether the pane has been killed.
    killed: bool,
}

impl SidecarPaneHandle for ZellijSidecarPane {
    fn pane_id(&self) -> &str {
        &self.tracking_id
    }

    fn send_keys(&self, keys: &str) -> MultiplexerResult<()> {
        // First move focus to the sidecar pane (below)
        let move_output = Command::new("zellij")
            .args(["action", "move-focus", "down"])
            .output()?;

        if !move_output.status.success() {
            let stderr = String::from_utf8_lossy(&move_output.stderr);
            return Err(MultiplexerError::CommandFailed(format!(
                "Failed to focus sidecar pane: {}",
                stderr
            )));
        }

        // Write the keys
        let write_output = Command::new("zellij")
            .args(["action", "write-chars", keys])
            .output()?;

        if !write_output.status.success() {
            let stderr = String::from_utf8_lossy(&write_output.stderr);
            // Try to return focus even if write failed
            let _ = Command::new("zellij")
                .args(["action", "move-focus", "up"])
                .output();
            return Err(MultiplexerError::CommandFailed(format!(
                "Failed to write chars: {}",
                stderr
            )));
        }

        // Send Enter key
        let enter_output = Command::new("zellij")
            .args(["action", "write", "10"]) // 10 is ASCII for newline
            .output()?;

        if !enter_output.status.success() {
            let stderr = String::from_utf8_lossy(&enter_output.stderr);
            // Try to return focus even if enter failed
            let _ = Command::new("zellij")
                .args(["action", "move-focus", "up"])
                .output();
            return Err(MultiplexerError::CommandFailed(format!(
                "Failed to send enter: {}",
                stderr
            )));
        }

        // Return focus to original pane
        let _ = Command::new("zellij")
            .args(["action", "move-focus", "up"])
            .output();

        Ok(())
    }

    fn kill(&self) -> MultiplexerResult<()> {
        // Move focus to sidecar pane and close it
        let move_output = Command::new("zellij")
            .args(["action", "move-focus", "down"])
            .output()?;

        if !move_output.status.success() {
            // Pane might already be gone
            let stderr = String::from_utf8_lossy(&move_output.stderr);
            debug!(
                "Could not focus sidecar pane (may be gone): {}",
                stderr
            );
            return Ok(());
        }

        // Close the focused pane
        let close_output = Command::new("zellij")
            .args(["action", "close-pane"])
            .output()?;

        if !close_output.status.success() {
            let stderr = String::from_utf8_lossy(&close_output.stderr);
            // Don't fail if pane is already gone
            if !stderr.contains("no pane") && !stderr.contains("not found") {
                return Err(MultiplexerError::CommandFailed(format!(
                    "Failed to close pane: {}",
                    stderr
                )));
            }
        }

        debug!(
            "Closed zellij sidecar pane (tracking id: {})",
            self.tracking_id
        );
        Ok(())
    }

    fn multiplexer_kind(&self) -> MultiplexerKind {
        MultiplexerKind::Zellij
    }
}

impl Drop for ZellijSidecarPane {
    fn drop(&mut self) {
        if !self.killed {
            if let Err(e) = self.kill() {
                warn!("Failed to cleanup zellij sidecar pane: {}", e);
            }
            self.killed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zellij_multiplexer_kind() {
        let mux = ZellijMultiplexer::new();
        assert_eq!(mux.kind(), MultiplexerKind::Zellij);
    }

    #[test]
    fn test_is_active_no_panic() {
        let mux = ZellijMultiplexer::new();
        let _ = mux.is_active();
    }

    #[test]
    fn test_session_name_no_panic() {
        let mux = ZellijMultiplexer::new();
        let _ = mux.session_name();
    }

    #[test]
    fn test_lines_to_percent() {
        // 15 lines should give ~37%
        let percent = ZellijMultiplexer::lines_to_percent(15);
        assert!((10..=50).contains(&percent));

        // Very small should clamp to 10%
        let small = ZellijMultiplexer::lines_to_percent(1);
        assert_eq!(small, 10);

        // Very large should clamp to 50%
        let large = ZellijMultiplexer::lines_to_percent(100);
        assert_eq!(large, 50);
    }

    #[test]
    fn test_create_sidecar_not_in_zellij() {
        // Skip if actually in zellij
        if std::env::var("ZELLIJ").is_ok() {
            return;
        }

        let mux = ZellijMultiplexer::new();
        let result = mux.create_sidecar_pane(SidecarOptions::default());
        assert!(matches!(result, Err(MultiplexerError::NotInMultiplexer)));
    }
}
