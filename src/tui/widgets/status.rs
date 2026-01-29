//! Status bar widget.

use crate::tui::FocusPanel;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
};

/// Widget for displaying the status bar with keybindings.
pub struct StatusWidget {
    /// Current focus panel.
    focus: FocusPanel,
    /// Number of pending permissions.
    pending_count: usize,
    /// Optional status message.
    message: Option<String>,
}

impl StatusWidget {
    /// Create a new status widget.
    pub fn new(focus: FocusPanel, pending_count: usize) -> Self {
        Self {
            focus,
            pending_count,
            message: None,
        }
    }

    /// Set a status message.
    pub fn with_message(mut self, message: Option<String>) -> Self {
        self.message = message;
        self
    }
}

impl Widget for StatusWidget {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let key_style = Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD);
        let action_style = Style::default().fg(Color::White);
        let sep_style = Style::default().fg(Color::DarkGray);

        // Build keybindings based on focus
        let mut spans = Vec::new();

        match self.focus {
            FocusPanel::Permissions => {
                spans.extend_from_slice(&[
                    Span::styled(" a ", key_style),
                    Span::styled("Allow ", action_style),
                    Span::styled(" b ", key_style),
                    Span::styled("Block ", action_style),
                    Span::styled(" A ", key_style),
                    Span::styled("Always Allow ", action_style),
                    Span::styled(" B ", key_style),
                    Span::styled("Always Block ", action_style),
                    Span::styled("|", sep_style),
                ]);
            }
            FocusPanel::Ports => {
                spans.extend_from_slice(&[
                    Span::styled(" p ", key_style),
                    Span::styled("Bridge Port ", action_style),
                    Span::styled("|", sep_style),
                ]);
            }
            FocusPanel::Logs => {
                // No special actions for logs
            }
        }

        // Common keybindings
        spans.extend_from_slice(&[
            Span::styled(" j/k ", key_style),
            Span::styled("Navigate ", action_style),
            Span::styled(" Tab ", key_style),
            Span::styled("Switch Panel ", action_style),
            Span::styled(" m ", key_style),
            Span::styled("Allowlist ", action_style),
            Span::styled(" q ", key_style),
            Span::styled("Quit ", action_style),
        ]);

        // Add pending count if any
        if self.pending_count > 0 {
            spans.extend_from_slice(&[
                Span::styled("|", sep_style),
                Span::styled(
                    format!(" {} pending ", self.pending_count),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]);
        }

        // Add status message if any
        if let Some(msg) = self.message {
            spans.extend_from_slice(&[
                Span::styled("|", sep_style),
                Span::styled(format!(" {} ", msg), Style::default().fg(Color::Green)),
            ]);
        }

        let line = Line::from(spans);
        let paragraph = Paragraph::new(line).style(Style::default().bg(Color::DarkGray));

        paragraph.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_widget_creation() {
        let widget = StatusWidget::new(FocusPanel::Permissions, 5);
        assert_eq!(widget.focus, FocusPanel::Permissions);
        assert_eq!(widget.pending_count, 5);
    }

    #[test]
    fn test_status_with_message() {
        let widget = StatusWidget::new(FocusPanel::Logs, 0)
            .with_message(Some("Test message".to_string()));
        assert!(widget.message.is_some());
    }
}
