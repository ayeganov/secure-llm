//! Keyboard input handling for TUI.
//!
//! # Keybindings
//!
//! | Key | Action |
//! |-----|--------|
//! | `a` / `y` | Allow (session only) |
//! | `b` / `n` | Block (session only) |
//! | `A` / `Y` | Always allow (persist to allowlist) |
//! | `B` / `N` | Always block (persist) |
//! | `j` / Down | Move selection down |
//! | `k` / Up | Move selection up |
//! | Tab | Cycle focus between panels |
//! | Shift+Tab | Cycle focus backwards |
//! | `p` / Enter | Bridge selected port |
//! | `s` | Stop bridge for selected port |
//! | `q` / Esc | Exit TUI |

use crate::tui::{FocusPanel, TuiApp};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

/// Result of handling an input event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputResult {
    /// Event was handled, continue running.
    Handled,
    /// Event was not handled (unknown key).
    NotHandled,
    /// User requested quit.
    Quit,
}

/// Handle a crossterm event.
///
/// Returns the result of handling the event.
pub async fn handle_event(app: &mut TuiApp, event: Event) -> InputResult {
    match event {
        Event::Key(key) => handle_key(app, key).await,
        Event::Resize(_, _) => InputResult::Handled, // Terminal resized, just redraw
        _ => InputResult::NotHandled,
    }
}

/// Handle a key event.
async fn handle_key(app: &mut TuiApp, key: KeyEvent) -> InputResult {
    // Handle quit keys globally
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.quit();
            return InputResult::Quit;
        }
        _ => {}
    }

    // Handle navigation keys globally
    match key.code {
        KeyCode::Tab => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.focus_prev();
            } else {
                app.focus_next();
            }
            return InputResult::Handled;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.select_down();
            return InputResult::Handled;
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.select_up();
            return InputResult::Handled;
        }
        _ => {}
    }

    // Handle panel-specific keys
    match app.focus() {
        FocusPanel::Permissions => handle_permission_keys(app, key).await,
        FocusPanel::Ports => handle_port_keys(app, key).await,
        FocusPanel::Logs => handle_log_keys(app, key).await,
    }
}

/// Handle keys specific to the permissions panel.
async fn handle_permission_keys(app: &mut TuiApp, key: KeyEvent) -> InputResult {
    match key.code {
        // Allow (session only)
        KeyCode::Char('a') | KeyCode::Char('y') => {
            app.allow_selected().await;
            InputResult::Handled
        }
        // Block (session only)
        KeyCode::Char('b') | KeyCode::Char('n') => {
            app.block_selected().await;
            InputResult::Handled
        }
        // Always allow (persist)
        KeyCode::Char('A') | KeyCode::Char('Y') => {
            app.always_allow_selected().await;
            InputResult::Handled
        }
        // Always block (persist)
        KeyCode::Char('B') | KeyCode::Char('N') => {
            app.always_block_selected().await;
            InputResult::Handled
        }
        _ => InputResult::NotHandled,
    }
}

/// Handle keys specific to the ports panel.
async fn handle_port_keys(app: &mut TuiApp, key: KeyEvent) -> InputResult {
    match key.code {
        // Bridge port
        KeyCode::Char('p') | KeyCode::Enter => {
            app.bridge_selected_port().await;
            InputResult::Handled
        }
        // Stop bridge
        KeyCode::Char('s') => {
            app.stop_selected_bridge().await;
            InputResult::Handled
        }
        _ => InputResult::NotHandled,
    }
}

/// Handle keys specific to the logs panel.
async fn handle_log_keys(_app: &mut TuiApp, _key: KeyEvent) -> InputResult {
    // Logs panel is read-only, no special keys
    InputResult::NotHandled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::channel::create_channel_pair;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use tokio::sync::watch;

    fn create_test_app() -> (TuiApp, crate::control::ProxyChannels) {
        let (proxy_channels, tui_channels) = create_channel_pair();
        let (_, shutdown_rx) = watch::channel(false);
        let app = TuiApp::new(tui_channels, shutdown_rx);
        (app, proxy_channels)
    }

    fn make_key_event(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn make_key_event_with_modifiers(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[tokio::test]
    async fn test_quit_keys() {
        let (mut app, _proxy) = create_test_app();

        let result = handle_key(&mut app, make_key_event(KeyCode::Char('q'))).await;
        assert_eq!(result, InputResult::Quit);
        assert!(app.should_quit());
    }

    #[tokio::test]
    async fn test_esc_quit() {
        let (mut app, _proxy) = create_test_app();

        let result = handle_key(&mut app, make_key_event(KeyCode::Esc)).await;
        assert_eq!(result, InputResult::Quit);
    }

    #[tokio::test]
    async fn test_tab_navigation() {
        let (mut app, _proxy) = create_test_app();

        assert_eq!(app.focus(), FocusPanel::Permissions);

        handle_key(&mut app, make_key_event(KeyCode::Tab)).await;
        assert_eq!(app.focus(), FocusPanel::Ports);

        handle_key(&mut app, make_key_event(KeyCode::Tab)).await;
        assert_eq!(app.focus(), FocusPanel::Logs);

        handle_key(&mut app, make_key_event(KeyCode::Tab)).await;
        assert_eq!(app.focus(), FocusPanel::Permissions);
    }

    #[tokio::test]
    async fn test_shift_tab_navigation() {
        let (mut app, _proxy) = create_test_app();

        assert_eq!(app.focus(), FocusPanel::Permissions);

        handle_key(
            &mut app,
            make_key_event_with_modifiers(KeyCode::Tab, KeyModifiers::SHIFT),
        )
        .await;
        assert_eq!(app.focus(), FocusPanel::Logs);
    }

    #[tokio::test]
    async fn test_jk_navigation() {
        let (mut app, _proxy) = create_test_app();

        // j moves down
        let result = handle_key(&mut app, make_key_event(KeyCode::Char('j'))).await;
        assert_eq!(result, InputResult::Handled);

        // k moves up
        let result = handle_key(&mut app, make_key_event(KeyCode::Char('k'))).await;
        assert_eq!(result, InputResult::Handled);
    }

    #[tokio::test]
    async fn test_arrow_navigation() {
        let (mut app, _proxy) = create_test_app();

        let result = handle_key(&mut app, make_key_event(KeyCode::Down)).await;
        assert_eq!(result, InputResult::Handled);

        let result = handle_key(&mut app, make_key_event(KeyCode::Up)).await;
        assert_eq!(result, InputResult::Handled);
    }
}
