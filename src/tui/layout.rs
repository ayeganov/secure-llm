//! TUI layout definitions.
//!
//! Defines the layout structure for the TUI panels:
//!
//! ```text
//! ┌────────────────────┬────────────────────┐
//! │                    │                    │
//! │   Permissions      │      Ports         │
//! │                    │                    │
//! ├────────────────────┴────────────────────┤
//! │                                         │
//! │                 Logs                    │
//! │                                         │
//! ├─────────────────────────────────────────┤
//! │ Status Bar: keybindings, pending count  │
//! └─────────────────────────────────────────┘
//! ```

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Layout constraints for the TUI.
#[derive(Debug, Clone)]
pub struct TuiLayout {
    /// Area for permissions panel.
    pub permissions: Rect,
    /// Area for ports panel.
    pub ports: Rect,
    /// Area for logs panel.
    pub logs: Rect,
    /// Area for status bar.
    pub status: Rect,
}

impl TuiLayout {
    /// Compute the layout for a given terminal area.
    pub fn compute(area: Rect) -> Self {
        // Split vertically: [top panels] [logs] [status]
        let vertical = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(40), // Top panels
                Constraint::Min(5),         // Logs (fill remaining)
                Constraint::Length(1),      // Status bar
            ])
            .split(area);

        let top_panels = vertical[0];
        let logs = vertical[1];
        let status = vertical[2];

        // Split top panels horizontally: [permissions] [ports]
        let horizontal = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50), // Permissions
                Constraint::Percentage(50), // Ports
            ])
            .split(top_panels);

        let permissions = horizontal[0];
        let ports = horizontal[1];

        Self {
            permissions,
            ports,
            logs,
            status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_computation() {
        let area = Rect::new(0, 0, 80, 24);
        let layout = TuiLayout::compute(area);

        // Permissions and ports should be side by side
        assert_eq!(layout.permissions.y, layout.ports.y);

        // Logs should be below the top panels
        assert!(layout.logs.y > layout.permissions.y);

        // Status should be at the bottom
        assert!(layout.status.y > layout.logs.y);
        assert_eq!(layout.status.height, 1);
    }

    #[test]
    fn test_layout_widths() {
        let area = Rect::new(0, 0, 100, 30);
        let layout = TuiLayout::compute(area);

        // Permissions and ports should each be ~50% width
        assert_eq!(layout.permissions.width, 50);
        assert_eq!(layout.ports.width, 50);

        // Logs and status should span full width
        assert_eq!(layout.logs.width, 100);
        assert_eq!(layout.status.width, 100);
    }
}
