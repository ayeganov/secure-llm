//! TUI event loop runner.
//!
//! This module provides the main event loop that:
//! - Processes terminal events (keyboard, resize)
//! - Processes messages from the proxy
//! - Renders the UI

use super::app::TuiApp;
use super::input::{handle_event, InputResult};
use super::layout::TuiLayout;
use super::widgets::{LogsWidget, PendingWidget, PortsWidget, StatusWidget};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Frame, Terminal};
use std::io::{self, Stdout};
use std::panic;
use std::time::Duration;
use tracing::{debug, error, info};

/// TUI runner that manages the terminal and event loop.
pub struct TuiRunner {
    /// The terminal backend.
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TuiRunner {
    /// Initialize the terminal for TUI mode.
    ///
    /// This enables raw mode and enters an alternate screen.
    pub fn new() -> io::Result<Self> {
        // Setup panic hook to restore terminal on panic
        let original_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            // Try to restore terminal
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
            original_hook(panic_info);
        }));

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        info!("TUI initialized");

        Ok(Self { terminal })
    }

    /// Restore the terminal to normal mode.
    pub fn restore(&mut self) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        self.terminal.show_cursor()?;

        info!("TUI restored");

        Ok(())
    }

    /// Run the TUI event loop.
    ///
    /// This is the main loop that processes events and renders the UI.
    pub async fn run(&mut self, app: &mut TuiApp) -> io::Result<()> {
        let tick_rate = Duration::from_millis(100);

        loop {
            // Check for shutdown
            if app.check_shutdown() {
                debug!("TUI received shutdown signal");
                break;
            }

            // Process any pending proxy messages
            while app.try_process_message() {
                // Keep processing until no more messages
            }

            // Update waiting times
            app.update_waiting_times();

            // Render the UI
            self.terminal.draw(|frame| render_ui(frame, app))?;

            // Check if we should quit
            if app.should_quit() {
                break;
            }

            // Poll for terminal events with timeout
            if event::poll(tick_rate)? {
                let event = event::read()?;
                let result = handle_event(app, event).await;

                if result == InputResult::Quit {
                    break;
                }
            }
        }

        Ok(())
    }
}

impl Drop for TuiRunner {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            error!("Failed to restore terminal: {}", e);
        }
    }
}

/// Render the complete UI.
fn render_ui(frame: &mut Frame, app: &TuiApp) {
    let layout = TuiLayout::compute(frame.area());

    // Render permissions panel
    let pending_widget = PendingWidget::new(
        app.pending_permissions(),
        app.focus(),
        app.permission_selection(),
    );
    frame.render_widget(pending_widget, layout.permissions);

    // Render ports panel
    let ports_widget = PortsWidget::new(
        app.detected_ports(),
        app.focus(),
        app.port_selection(),
    );
    frame.render_widget(ports_widget, layout.ports);

    // Render logs panel
    let logs_widget = LogsWidget::new(app.logs(), app.focus(), app.log_selection());
    frame.render_widget(logs_widget, layout.logs);

    // Render status bar
    let status_widget = StatusWidget::new(app.focus(), app.pending_permissions().len())
        .with_message(app.status_message().map(String::from));
    frame.render_widget(status_widget, layout.status);
}

/// Run the TUI with panic recovery.
///
/// If the TUI panics, this function will attempt to restore the terminal
/// and return the panic error.
pub async fn run_with_recovery(app: &mut TuiApp) -> Result<(), String> {
    // Use catch_unwind for panic recovery
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let mut runner = TuiRunner::new().map_err(|e| e.to_string())?;
            runner.run(app).await.map_err(|e| e.to_string())
        })
    }));

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(panic_error) => {
            // Try to get panic message
            let msg = if let Some(s) = panic_error.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_error.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };

            error!("TUI panicked: {}", msg);
            Err(format!("TUI panic: {}", msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_compute() {
        use ratatui::layout::Rect;

        let area = Rect::new(0, 0, 80, 24);
        let layout = TuiLayout::compute(area);

        // Basic sanity checks
        assert!(layout.permissions.width > 0);
        assert!(layout.ports.width > 0);
        assert!(layout.logs.width > 0);
        assert_eq!(layout.status.height, 1);
    }
}
