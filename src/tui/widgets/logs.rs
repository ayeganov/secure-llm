//! Log stream widget.

use crate::control::protocol::LogLevel;
use crate::tui::{FocusPanel, LogEntry};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget},
};
use std::collections::VecDeque;

/// Widget for displaying log messages.
pub struct LogsWidget<'a> {
    /// The log entries to display.
    logs: &'a VecDeque<LogEntry>,
    /// Whether this panel has focus.
    focused: bool,
    /// Selected index.
    selected: usize,
}

impl<'a> LogsWidget<'a> {
    /// Create a new logs widget.
    pub fn new(logs: &'a VecDeque<LogEntry>, focus: FocusPanel, selected: usize) -> Self {
        Self {
            logs,
            focused: focus == FocusPanel::Logs,
            selected,
        }
    }

    /// Get the color for a log level.
    fn level_color(level: LogLevel) -> Color {
        match level {
            LogLevel::Debug => Color::DarkGray,
            LogLevel::Info => Color::Blue,
            LogLevel::Warn => Color::Yellow,
            LogLevel::Error => Color::Red,
        }
    }
}

impl Widget for LogsWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Create list items
        let items: Vec<ListItem> = self
            .logs
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let is_selected = i == self.selected && self.focused;
                let level_color = Self::level_color(entry.level);

                let timestamp = entry.timestamp.format("%H:%M:%S");

                let msg_style = if is_selected {
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                let line = Line::from(vec![
                    Span::styled(
                        format!("{}", timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        format!("{:5}", entry.level),
                        Style::default().fg(level_color),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        format!("[{}]", entry.category),
                        Style::default().fg(Color::Magenta),
                    ),
                    Span::raw(" "),
                    Span::styled(&entry.message, msg_style),
                ]);

                ListItem::new(line)
            })
            .collect();

        // Create block with title
        let title = format!(" Logs ({}) ", self.logs.len());
        let border_style = if self.focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style);

        // Render the list
        let mut state = ListState::default();
        if self.focused && !self.logs.is_empty() {
            state.select(Some(self.selected));
        }

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            );

        StatefulWidget::render(list, area, buf, &mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::protocol::EventCategory;
    use chrono::Utc;

    #[test]
    fn test_logs_widget_creation() {
        let mut logs = VecDeque::new();
        logs.push_back(LogEntry {
            level: LogLevel::Info,
            category: EventCategory::Network,
            message: "Test message".to_string(),
            timestamp: Utc::now(),
        });

        let widget = LogsWidget::new(&logs, FocusPanel::Logs, 0);
        assert!(widget.focused);
    }

    #[test]
    fn test_level_colors() {
        assert_eq!(LogsWidget::level_color(LogLevel::Debug), Color::DarkGray);
        assert_eq!(LogsWidget::level_color(LogLevel::Info), Color::Blue);
        assert_eq!(LogsWidget::level_color(LogLevel::Warn), Color::Yellow);
        assert_eq!(LogsWidget::level_color(LogLevel::Error), Color::Red);
    }
}
