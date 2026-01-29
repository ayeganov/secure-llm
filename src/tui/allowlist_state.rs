//! Allowlist modal state management.
//!
//! This module provides the state for the allowlist management modal
//! that allows users to view and remove domains from their persistent allowlist.

use std::collections::HashSet;
use std::sync::Arc;

use crate::config::ConfigLoader;

/// State for the allowlist management modal.
pub struct AllowlistModalState {
    /// Domains loaded from the allowlist file.
    domains: Vec<String>,
    /// Selected domain indices (checked checkboxes).
    selected: HashSet<usize>,
    /// Current cursor position.
    cursor: usize,
    /// Scroll offset for long lists.
    scroll_offset: usize,
    /// Whether the modal is visible.
    visible: bool,
}

impl Default for AllowlistModalState {
    fn default() -> Self {
        Self::new()
    }
}

impl AllowlistModalState {
    /// Create a new allowlist modal state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            selected: HashSet::new(),
            cursor: 0,
            scroll_offset: 0,
            visible: false,
        }
    }

    /// Load domains from the allowlist file.
    pub fn load_domains(&mut self, loader: &ConfigLoader) {
        self.domains = loader
            .load_user_allowlist()
            .map(|a| a.domains.allowed)
            .unwrap_or_default();
        self.selected.clear();
        self.cursor = 0;
        self.scroll_offset = 0;
    }

    /// Get the list of domains.
    #[must_use]
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// Show the modal.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the modal.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Check if the modal is visible.
    #[must_use]
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Get the current cursor position.
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Get the scroll offset.
    #[must_use]
    pub fn scroll_offset(&self) -> usize {
        self.scroll_offset
    }

    /// Check if a domain at the given index is selected.
    #[must_use]
    pub fn is_selected(&self, index: usize) -> bool {
        self.selected.contains(&index)
    }

    /// Get the number of selected domains.
    #[must_use]
    pub fn selected_count(&self) -> usize {
        self.selected.len()
    }

    /// Toggle the selection at the current cursor position.
    pub fn toggle_selected(&mut self) {
        if self.cursor < self.domains.len() {
            if self.selected.contains(&self.cursor) {
                self.selected.remove(&self.cursor);
            } else {
                self.selected.insert(self.cursor);
            }
        }
    }

    /// Select all domains.
    pub fn select_all(&mut self) {
        for i in 0..self.domains.len() {
            self.selected.insert(i);
        }
    }

    /// Deselect all domains.
    pub fn select_none(&mut self) {
        self.selected.clear();
    }

    /// Move cursor up.
    pub fn cursor_up(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            // Adjust scroll if needed
            if self.cursor < self.scroll_offset {
                self.scroll_offset = self.cursor;
            }
        }
    }

    /// Move cursor down.
    pub fn cursor_down(&mut self) {
        if !self.domains.is_empty() && self.cursor < self.domains.len() - 1 {
            self.cursor += 1;
        }
    }

    /// Adjust scroll offset for a given visible height.
    pub fn adjust_scroll(&mut self, visible_height: usize) {
        if visible_height == 0 {
            return;
        }
        // Ensure cursor is visible
        if self.cursor >= self.scroll_offset + visible_height {
            self.scroll_offset = self.cursor - visible_height + 1;
        }
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        }
    }

    /// Remove selected domains from the allowlist file.
    ///
    /// Returns the number of domains removed.
    pub fn remove_selected(&mut self, loader: &Arc<ConfigLoader>) -> usize {
        if self.selected.is_empty() {
            return 0;
        }

        // Collect domains to remove (in reverse order to maintain indices)
        let mut indices: Vec<usize> = self.selected.iter().copied().collect();
        indices.sort();
        indices.reverse();

        let mut removed = 0;
        for idx in indices {
            if idx < self.domains.len() {
                let domain = &self.domains[idx];
                if loader.remove_from_allowlist(domain).is_ok() {
                    removed += 1;
                }
            }
        }

        // Reload domains after removal
        self.load_domains(loader);

        // Adjust cursor if needed
        if !self.domains.is_empty() {
            self.cursor = self.cursor.min(self.domains.len() - 1);
        } else {
            self.cursor = 0;
        }

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let state = AllowlistModalState::new();
        assert!(state.domains.is_empty());
        assert!(!state.is_visible());
        assert_eq!(state.cursor(), 0);
        assert_eq!(state.selected_count(), 0);
    }

    #[test]
    fn test_visibility() {
        let mut state = AllowlistModalState::new();
        assert!(!state.is_visible());
        state.show();
        assert!(state.is_visible());
        state.hide();
        assert!(!state.is_visible());
    }

    #[test]
    fn test_selection() {
        let mut state = AllowlistModalState::new();
        state.domains = vec![
            "example.com".to_string(),
            "test.com".to_string(),
            "other.com".to_string(),
        ];

        // Toggle selection at cursor 0
        state.toggle_selected();
        assert!(state.is_selected(0));
        assert_eq!(state.selected_count(), 1);

        // Toggle again to deselect
        state.toggle_selected();
        assert!(!state.is_selected(0));
        assert_eq!(state.selected_count(), 0);
    }

    #[test]
    fn test_select_all_none() {
        let mut state = AllowlistModalState::new();
        state.domains = vec![
            "example.com".to_string(),
            "test.com".to_string(),
            "other.com".to_string(),
        ];

        state.select_all();
        assert_eq!(state.selected_count(), 3);

        state.select_none();
        assert_eq!(state.selected_count(), 0);
    }

    #[test]
    fn test_cursor_navigation() {
        let mut state = AllowlistModalState::new();
        state.domains = vec![
            "example.com".to_string(),
            "test.com".to_string(),
            "other.com".to_string(),
        ];

        assert_eq!(state.cursor(), 0);
        state.cursor_down();
        assert_eq!(state.cursor(), 1);
        state.cursor_down();
        assert_eq!(state.cursor(), 2);
        // Should not go past end
        state.cursor_down();
        assert_eq!(state.cursor(), 2);

        state.cursor_up();
        assert_eq!(state.cursor(), 1);
        state.cursor_up();
        assert_eq!(state.cursor(), 0);
        // Should not go below 0
        state.cursor_up();
        assert_eq!(state.cursor(), 0);
    }

    #[test]
    fn test_cursor_empty_list() {
        let mut state = AllowlistModalState::new();

        state.cursor_down();
        assert_eq!(state.cursor(), 0);
        state.cursor_up();
        assert_eq!(state.cursor(), 0);
    }
}
