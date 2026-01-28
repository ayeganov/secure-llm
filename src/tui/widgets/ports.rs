//! Detected ports list widget.

use crate::control::protocol::DetectedPort;
use crate::tui::FocusPanel;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget},
};

/// Widget for displaying detected ports.
pub struct PortsWidget<'a> {
    /// The detected ports to display.
    ports: &'a [DetectedPort],
    /// Whether this panel has focus.
    focused: bool,
    /// Selected index.
    selected: usize,
}

impl<'a> PortsWidget<'a> {
    /// Create a new ports widget.
    pub fn new(ports: &'a [DetectedPort], focus: FocusPanel, selected: usize) -> Self {
        Self {
            ports,
            focused: focus == FocusPanel::Ports,
            selected,
        }
    }
}

impl Widget for PortsWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Create list items
        let items: Vec<ListItem> = self
            .ports
            .iter()
            .enumerate()
            .map(|(i, port)| {
                let is_selected = i == self.selected && self.focused;

                let status_span = if port.forwarded {
                    Span::styled(
                        "[BRIDGED - s:stop]",
                        Style::default().fg(Color::Green),
                    )
                } else {
                    Span::styled(
                        "[p:bridge]",
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )
                };

                let port_style = if is_selected {
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Cyan)
                };

                let addr_style = Style::default().fg(Color::Gray);

                let line = Line::from(vec![
                    Span::styled(format!("{:5}", port.port), port_style),
                    Span::raw(" "),
                    Span::styled(&port.local_addr, addr_style),
                    Span::raw(" "),
                    status_span,
                    if let Some(ref name) = port.process_name {
                        Span::styled(format!(" ({})", name), Style::default().fg(Color::Yellow))
                    } else {
                        Span::raw("")
                    },
                ]);

                ListItem::new(line)
            })
            .collect();

        // Create block with title (show help when focused)
        let title = if self.focused && !self.ports.is_empty() {
            format!(" Ports ({}) - p:bridge s:stop ", self.ports.len())
        } else {
            format!(" Ports ({}) ", self.ports.len())
        };
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
        if self.focused && !self.ports.is_empty() {
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
    fn test_ports_widget_creation() {
        let ports = vec![DetectedPort {
            id: Uuid::new_v4(),
            port: 3000,
            local_addr: "0.0.0.0".to_string(),
            process_name: Some("node".to_string()),
            forwarded: false,
            timestamp: Utc::now(),
        }];

        let widget = PortsWidget::new(&ports, FocusPanel::Ports, 0);
        assert!(widget.focused);
    }
}
