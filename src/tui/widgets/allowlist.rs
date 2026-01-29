//! Allowlist management modal widget.

use crate::tui::allowlist_state::AllowlistModalState;
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget},
};

/// Widget for displaying the allowlist management modal.
pub struct AllowlistWidget<'a> {
    /// The modal state.
    state: &'a AllowlistModalState,
    /// Visible height for domain list (computed from area).
    visible_height: usize,
}

impl<'a> AllowlistWidget<'a> {
    /// Create a new allowlist widget.
    pub fn new(state: &'a AllowlistModalState) -> Self {
        Self {
            state,
            visible_height: 10, // Default, will be adjusted during render
        }
    }

    /// Set the visible height for the domain list.
    pub fn with_visible_height(mut self, height: usize) -> Self {
        self.visible_height = height;
        self
    }
}

impl Widget for AllowlistWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Clear the area first
        Clear.render(area, buf);

        let domains = self.state.domains();
        let domain_count = format!(" ({} domains) ", domains.len());

        // Create title with highlighted warning
        let title = Line::from(vec![
            Span::styled(
                " Double Check the Allow List ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(domain_count, Style::default().fg(Color::Cyan)),
        ]);

        // Create main block
        let block = Block::default()
            .title(title)
            .title_alignment(Alignment::Center)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = block.inner(area);
        block.render(area, buf);

        if inner.height < 3 {
            return;
        }

        // Split inner area: domain list + footer
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),    // Domain list
                Constraint::Length(2), // Footer with keybindings
            ])
            .split(inner);

        let list_area = layout[0];
        let footer_area = layout[1];

        // Render domain list
        self.render_domain_list(list_area, buf);

        // Render footer
        self.render_footer(footer_area, buf);
    }
}

impl AllowlistWidget<'_> {
    fn render_domain_list(&self, area: Rect, buf: &mut Buffer) {
        let domains = self.state.domains();

        if domains.is_empty() {
            let msg = Paragraph::new("No domains in allowlist")
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Center);
            msg.render(area, buf);
            return;
        }

        let visible_height = area.height as usize;
        let scroll_offset = self.state.scroll_offset();
        let cursor = self.state.cursor();

        // Render each visible domain
        for (i, row) in (0..visible_height).enumerate() {
            let domain_idx = scroll_offset + i;
            if domain_idx >= domains.len() {
                break;
            }

            let y = area.y + row as u16;
            if y >= area.y + area.height {
                break;
            }

            let domain = &domains[domain_idx];
            let is_cursor = domain_idx == cursor;
            let is_selected = self.state.is_selected(domain_idx);

            // Build the line
            let cursor_marker = if is_cursor { "> " } else { "  " };
            let checkbox = if is_selected { "[x] " } else { "[ ] " };

            // Style based on cursor position
            let domain_style = if is_cursor {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Cyan)
            };

            let checkbox_style = if is_selected {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let cursor_style = if is_cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Render cursor marker
            let x = area.x;
            buf.set_string(x, y, cursor_marker, cursor_style);

            // Render checkbox
            buf.set_string(x + 2, y, checkbox, checkbox_style);

            // Render domain (truncate if necessary)
            let max_domain_width = area.width.saturating_sub(6) as usize;
            let display_domain = if domain.len() > max_domain_width {
                format!("{}...", &domain[..max_domain_width.saturating_sub(3)])
            } else {
                domain.clone()
            };
            buf.set_string(x + 6, y, &display_domain, domain_style);

            // Highlight entire row if cursor
            if is_cursor {
                for col in 0..area.width {
                    if let Some(cell) = buf.cell_mut((area.x + col, y)) {
                        cell.set_bg(Color::DarkGray);
                    }
                }
            }
        }
    }

    fn render_footer(&self, area: Rect, buf: &mut Buffer) {
        let key_style = Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD);
        let action_style = Style::default().fg(Color::White);
        let sep_style = Style::default().fg(Color::DarkGray);

        // First line: selection controls
        let line1 = Line::from(vec![
            Span::styled(" Space ", key_style),
            Span::styled("Toggle ", action_style),
            Span::styled(" a ", key_style),
            Span::styled("All ", action_style),
            Span::styled(" n ", key_style),
            Span::styled("None ", action_style),
            Span::styled(" j/k ", key_style),
            Span::styled("Navigate ", action_style),
        ]);

        // Second line: actions
        let selected_count = self.state.selected_count();
        let remove_text = if selected_count > 0 {
            format!("Remove {} selected ", selected_count)
        } else {
            "Remove selected ".to_string()
        };

        let remove_style = if selected_count > 0 {
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD)
        } else {
            action_style
        };

        let line2 = Line::from(vec![
            Span::styled(" r ", key_style),
            Span::styled(remove_text, remove_style),
            Span::styled("|", sep_style),
            Span::styled(" Enter ", key_style),
            Span::styled("Accept ", Style::default().fg(Color::Green)),
            Span::styled("|", sep_style),
            Span::styled(" Esc ", key_style),
            Span::styled("Close ", action_style),
        ]);

        if area.height >= 2 {
            let p1 = Paragraph::new(line1).alignment(Alignment::Center);
            let p2 = Paragraph::new(line2).alignment(Alignment::Center);

            p1.render(
                Rect {
                    y: area.y,
                    height: 1,
                    ..area
                },
                buf,
            );
            p2.render(
                Rect {
                    y: area.y + 1,
                    height: 1,
                    ..area
                },
                buf,
            );
        } else if area.height >= 1 {
            let p1 = Paragraph::new(line1).alignment(Alignment::Center);
            p1.render(area, buf);
        }
    }
}

/// Compute a centered rectangle with given percentage dimensions.
pub fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_centered_rect() {
        let area = Rect::new(0, 0, 100, 50);
        let centered = centered_rect(60, 70, area);

        // Should be roughly centered
        assert!(centered.x > 0);
        assert!(centered.y > 0);
        assert!(centered.x + centered.width <= area.width);
        assert!(centered.y + centered.height <= area.height);
    }

    #[test]
    fn test_widget_creation() {
        let state = AllowlistModalState::new();
        let widget = AllowlistWidget::new(&state);
        assert_eq!(widget.visible_height, 10);
    }
}
