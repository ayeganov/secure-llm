//! Pending permissions list widget.

use crate::control::protocol::PendingPermission;
use crate::tui::FocusPanel;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget},
};

/// Widget for displaying pending permission requests.
pub struct PendingWidget<'a> {
    /// The pending permissions to display.
    permissions: &'a [PendingPermission],
    /// Whether this panel has focus.
    focused: bool,
    /// Selected index.
    selected: usize,
}

impl<'a> PendingWidget<'a> {
    /// Create a new pending permissions widget.
    pub fn new(permissions: &'a [PendingPermission], focus: FocusPanel, selected: usize) -> Self {
        Self {
            permissions,
            focused: focus == FocusPanel::Permissions,
            selected,
        }
    }
}

impl Widget for PendingWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Create list items
        let items: Vec<ListItem> = self
            .permissions
            .iter()
            .enumerate()
            .map(|(i, perm)| {
                let is_selected = i == self.selected && self.focused;

                let waiting_style = if perm.waiting_secs > 20 {
                    Style::default().fg(Color::Red)
                } else if perm.waiting_secs > 10 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Gray)
                };

                let line = Line::from(vec![
                    Span::styled(
                        perm.domain.to_string(),
                        if is_selected {
                            Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Cyan)
                        },
                    ),
                    Span::raw(":"),
                    Span::styled(format!("{}", perm.port), Style::default().fg(Color::Green)),
                    Span::raw(" "),
                    Span::styled(format!("({}s)", perm.waiting_secs), waiting_style),
                ]);

                ListItem::new(line)
            })
            .collect();

        // Create block with title
        let title = format!(
            " Permissions ({}) ",
            self.permissions.len()
        );
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
        if self.focused && !self.permissions.is_empty() {
            state.select(Some(self.selected));
        }

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        StatefulWidget::render(list, area, buf, &mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_pending_widget_creation() {
        let permissions = vec![PendingPermission {
            id: Uuid::new_v4(),
            domain: "example.com".to_string(),
            port: 443,
            waiting_secs: 5,
            timestamp: Utc::now(),
        }];

        let widget = PendingWidget::new(&permissions, FocusPanel::Permissions, 0);
        assert!(widget.focused);
    }
}
