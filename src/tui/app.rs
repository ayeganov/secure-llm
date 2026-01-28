//! TUI application state machine.
//!
//! The `TuiApp` manages all state for the terminal user interface:
//! - Pending permission requests (from proxy)
//! - Detected ports (from port monitor)
//! - Log messages
//! - UI focus and selection state

use crate::control::protocol::{
    Decision, DetectedPort, EventCategory, LogLevel, PendingPermission, ProxyToTui, TuiToProxy,
};
use crate::control::{ControlSocketClient, TuiChannels};
use chrono::Utc;
use std::collections::VecDeque;
use tokio::sync::watch;
use tracing::debug;

use super::state::{FocusPanel, LogEntry, MAX_DETECTED_PORTS, MAX_LOG_ENTRIES};
use super::transport::TuiTransport;

/// The TUI application state.
pub struct TuiApp {
    /// Communication transport with the proxy/control plane.
    transport: TuiTransport,
    /// Shutdown signal receiver.
    shutdown_rx: watch::Receiver<bool>,
    /// Pending permission requests.
    pending_permissions: Vec<PendingPermission>,
    /// Detected ports.
    detected_ports: Vec<DetectedPort>,
    /// Log entries (newest first).
    logs: VecDeque<LogEntry>,
    /// Which panel currently has focus.
    focus: FocusPanel,
    /// Selected index in permissions list.
    permission_selection: usize,
    /// Selected index in ports list.
    port_selection: usize,
    /// Selected index in logs list.
    log_selection: usize,
    /// Whether the app should quit.
    should_quit: bool,
    /// Status message to display.
    status_message: Option<String>,
}

impl TuiApp {
    /// Create a new TUI application with the given transport.
    fn with_transport(transport: TuiTransport, shutdown_rx: watch::Receiver<bool>) -> Self {
        Self {
            transport,
            shutdown_rx,
            pending_permissions: Vec::new(),
            detected_ports: Vec::new(),
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            focus: FocusPanel::Permissions,
            permission_selection: 0,
            port_selection: 0,
            log_selection: 0,
            should_quit: false,
            status_message: None,
        }
    }

    /// Create a new TUI application with channel-based transport.
    pub fn new(channels: TuiChannels, shutdown_rx: watch::Receiver<bool>) -> Self {
        Self::with_transport(TuiTransport::Channel(channels), shutdown_rx)
    }

    /// Create a new TUI application with socket-based transport.
    pub fn new_with_socket(client: ControlSocketClient, shutdown_rx: watch::Receiver<bool>) -> Self {
        let mut app = Self::with_transport(TuiTransport::Socket(client), shutdown_rx);

        app.add_log(
            LogLevel::Info,
            EventCategory::System,
            "TUI connected via socket IPC".to_string(),
        );

        app
    }

    /// Get the current focus panel.
    #[must_use]
    pub fn focus(&self) -> FocusPanel {
        self.focus
    }

    /// Get pending permissions.
    #[must_use]
    pub fn pending_permissions(&self) -> &[PendingPermission] {
        &self.pending_permissions
    }

    /// Get detected ports.
    #[must_use]
    pub fn detected_ports(&self) -> &[DetectedPort] {
        &self.detected_ports
    }

    /// Get log entries.
    #[must_use]
    pub fn logs(&self) -> &VecDeque<LogEntry> {
        &self.logs
    }

    /// Get current permission selection index.
    #[must_use]
    pub fn permission_selection(&self) -> usize {
        self.permission_selection
    }

    /// Get current port selection index.
    #[must_use]
    pub fn port_selection(&self) -> usize {
        self.port_selection
    }

    /// Get current log selection index.
    #[must_use]
    pub fn log_selection(&self) -> usize {
        self.log_selection
    }

    /// Check if app should quit.
    #[must_use]
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// Get the current status message.
    #[must_use]
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// Set the quit flag.
    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    /// Cycle focus to the next panel.
    pub fn focus_next(&mut self) {
        self.focus = self.focus.next();
    }

    /// Cycle focus to the previous panel.
    pub fn focus_prev(&mut self) {
        self.focus = self.focus.prev();
    }

    /// Move selection up in the focused panel.
    pub fn select_up(&mut self) {
        match self.focus {
            FocusPanel::Permissions => {
                if self.permission_selection > 0 {
                    self.permission_selection -= 1;
                }
            }
            FocusPanel::Ports => {
                if self.port_selection > 0 {
                    self.port_selection -= 1;
                }
            }
            FocusPanel::Logs => {
                if self.log_selection > 0 {
                    self.log_selection -= 1;
                }
            }
        }
    }

    /// Move selection down in the focused panel.
    pub fn select_down(&mut self) {
        match self.focus {
            FocusPanel::Permissions => {
                if !self.pending_permissions.is_empty()
                    && self.permission_selection < self.pending_permissions.len() - 1
                {
                    self.permission_selection += 1;
                }
            }
            FocusPanel::Ports => {
                if !self.detected_ports.is_empty()
                    && self.port_selection < self.detected_ports.len() - 1
                {
                    self.port_selection += 1;
                }
            }
            FocusPanel::Logs => {
                if !self.logs.is_empty() && self.log_selection < self.logs.len() - 1 {
                    self.log_selection += 1;
                }
            }
        }
    }

    /// Allow the currently selected permission (session only).
    pub async fn allow_selected(&mut self) {
        self.decide_permission(Decision::Allow, false).await;
    }

    /// Block the currently selected permission (session only).
    pub async fn block_selected(&mut self) {
        self.decide_permission(Decision::Block, false).await;
    }

    /// Always allow the currently selected permission (persist).
    pub async fn always_allow_selected(&mut self) {
        self.decide_permission(Decision::Allow, true).await;
    }

    /// Always block the currently selected permission (persist).
    pub async fn always_block_selected(&mut self) {
        self.decide_permission(Decision::Block, true).await;
    }

    /// Send a decision for the currently selected permission.
    async fn decide_permission(&mut self, decision: Decision, persist: bool) {
        if self.pending_permissions.is_empty() {
            return;
        }

        let idx = self.permission_selection.min(self.pending_permissions.len() - 1);
        let permission = &self.pending_permissions[idx];
        let id = permission.id;
        let domain = permission.domain.clone();

        let msg = TuiToProxy::PermissionDecision {
            id,
            decision,
            persist,
        };

        if self.transport.send(msg).await.is_ok() {
            self.pending_permissions.remove(idx);

            if !self.pending_permissions.is_empty() {
                self.permission_selection =
                    self.permission_selection.min(self.pending_permissions.len() - 1);
            } else {
                self.permission_selection = 0;
            }

            let persist_str = if persist { " (persistent)" } else { "" };
            self.add_log(
                LogLevel::Info,
                EventCategory::Policy,
                format!("{:?} {} {}{}", decision, domain, id, persist_str),
            );
        }
    }

    /// Bridge the currently selected port.
    pub async fn bridge_selected_port(&mut self) {
        if self.detected_ports.is_empty() {
            return;
        }

        let idx = self.port_selection.min(self.detected_ports.len() - 1);
        let port_info = &self.detected_ports[idx];

        // Don't bridge if already bridged
        if port_info.forwarded {
            return;
        }

        let id = port_info.id;
        let port = port_info.port;

        let msg = TuiToProxy::PortDecision {
            id,
            bridge: true,
            host_port: Some(port),
        };

        if self.transport.send(msg).await.is_ok() {
            if let Some(p) = self.detected_ports.get_mut(idx) {
                p.forwarded = true;
            }

            self.add_log(
                LogLevel::Info,
                EventCategory::Port,
                format!("Bridging port {}", port),
            );
        }
    }

    /// Stop bridging the currently selected port.
    pub async fn stop_selected_bridge(&mut self) {
        if self.detected_ports.is_empty() {
            return;
        }

        let idx = self.port_selection.min(self.detected_ports.len() - 1);
        let port_info = &self.detected_ports[idx];

        // Only stop if currently bridged
        if !port_info.forwarded {
            return;
        }

        let id = port_info.id;
        let port = port_info.port;

        let msg = TuiToProxy::StopBridge { id };

        if self.transport.send(msg).await.is_ok() {
            if let Some(p) = self.detected_ports.get_mut(idx) {
                p.forwarded = false;
            }

            self.add_log(
                LogLevel::Info,
                EventCategory::Port,
                format!("Stopping bridge for port {}", port),
            );
        }
    }

    /// Process incoming messages from the proxy.
    pub fn try_process_message(&mut self) -> bool {
        match self.transport.try_recv() {
            Some(msg) => {
                self.handle_proxy_message(msg);
                true
            }
            None => false,
        }
    }

    /// Check for shutdown signal.
    pub fn check_shutdown(&mut self) -> bool {
        if self.shutdown_rx.has_changed().unwrap_or(false)
            && *self.shutdown_rx.borrow() {
                self.should_quit = true;
                return true;
            }
        false
    }

    /// Handle a message from the proxy.
    fn handle_proxy_message(&mut self, msg: ProxyToTui) {
        match msg {
            ProxyToTui::PermissionRequest {
                id,
                domain,
                port,
                timestamp,
            } => {
                debug!("Received permission request for {}:{}", domain, port);
                self.pending_permissions.push(PendingPermission {
                    id,
                    domain: domain.clone(),
                    port,
                    waiting_secs: 0,
                    timestamp,
                });

                self.add_log(
                    LogLevel::Info,
                    EventCategory::Network,
                    format!("Permission request: {}:{}", domain, port),
                );

                if self.pending_permissions.len() == 1 {
                    self.focus = FocusPanel::Permissions;
                }
            }
            ProxyToTui::PortDetected {
                id,
                port,
                local_addr,
                process_name,
                timestamp,
            } => {
                debug!("Received port detection: {} on {}", port, local_addr);

                if !self.detected_ports.iter().any(|p| p.port == port) {
                    self.detected_ports.push(DetectedPort {
                        id,
                        port,
                        local_addr: local_addr.clone(),
                        process_name,
                        forwarded: false,
                        timestamp,
                    });

                    if self.detected_ports.len() > MAX_DETECTED_PORTS {
                        self.detected_ports.remove(0);
                    }

                    self.add_log(
                        LogLevel::Info,
                        EventCategory::Port,
                        format!("Port {} detected on {}", port, local_addr),
                    );
                }
            }
            ProxyToTui::LogEvent {
                level,
                category,
                message,
                timestamp,
            } => {
                self.logs.push_front(LogEntry {
                    level,
                    category,
                    message,
                    timestamp,
                });

                while self.logs.len() > MAX_LOG_ENTRIES {
                    self.logs.pop_back();
                }
            }
            ProxyToTui::PermissionCancelled { id, reason } => {
                debug!("Permission request {} cancelled: {}", id, reason);

                if let Some(pos) = self.pending_permissions.iter().position(|p| p.id == id) {
                    let perm = self.pending_permissions.remove(pos);

                    self.add_log(
                        LogLevel::Warn,
                        EventCategory::Network,
                        format!("Request cancelled: {} ({})", perm.domain, reason),
                    );

                    if !self.pending_permissions.is_empty() {
                        self.permission_selection =
                            self.permission_selection.min(self.pending_permissions.len() - 1);
                    } else {
                        self.permission_selection = 0;
                    }
                }
            }
            ProxyToTui::PortBridgeStarted {
                id,
                host_port,
                container_port,
            } => {
                debug!(
                    "Port bridge started: host:{} -> container:{}",
                    host_port, container_port
                );

                // Update the detected port's forwarded status
                if let Some(port) = self.detected_ports.iter_mut().find(|p| p.id == id) {
                    port.forwarded = true;
                }

                self.add_log(
                    LogLevel::Info,
                    EventCategory::Port,
                    format!(
                        "Port bridge started: localhost:{} -> sandbox:{}",
                        host_port, container_port
                    ),
                );
            }
            ProxyToTui::PortBridgeStopped {
                host_port,
                container_port,
                reason,
            } => {
                debug!(
                    "Port bridge stopped: host:{} -> container:{} ({})",
                    host_port, container_port, reason
                );

                // Update the detected port's forwarded status
                if let Some(port) = self
                    .detected_ports
                    .iter_mut()
                    .find(|p| p.port == container_port)
                {
                    port.forwarded = false;
                }

                self.add_log(
                    LogLevel::Info,
                    EventCategory::Port,
                    format!(
                        "Port bridge stopped: localhost:{} -> sandbox:{} ({})",
                        host_port, container_port, reason
                    ),
                );
            }
            ProxyToTui::PortClosed { id, port } => {
                debug!("Port {} closed", port);

                // Remove the port from detected list
                if let Some(pos) = self.detected_ports.iter().position(|p| p.id == id) {
                    self.detected_ports.remove(pos);

                    if !self.detected_ports.is_empty() {
                        self.port_selection =
                            self.port_selection.min(self.detected_ports.len() - 1);
                    } else {
                        self.port_selection = 0;
                    }

                    self.add_log(
                        LogLevel::Info,
                        EventCategory::Port,
                        format!("Port {} closed", port),
                    );
                }
            }
            ProxyToTui::Shutdown => {
                debug!("Received shutdown signal from proxy");
                self.should_quit = true;
            }
        }
    }

    /// Add a log entry.
    pub fn add_log(&mut self, level: LogLevel, category: EventCategory, message: String) {
        self.logs.push_front(LogEntry {
            level,
            category,
            message,
            timestamp: Utc::now(),
        });

        while self.logs.len() > MAX_LOG_ENTRIES {
            self.logs.pop_back();
        }
    }

    /// Update waiting times for pending permissions.
    pub fn update_waiting_times(&mut self) {
        let now = Utc::now();
        for perm in &mut self.pending_permissions {
            perm.waiting_secs = (now - perm.timestamp).num_seconds().max(0) as u64;
        }
    }

    /// Get the selected permission if any.
    #[must_use]
    pub fn selected_permission(&self) -> Option<&PendingPermission> {
        if self.pending_permissions.is_empty() {
            None
        } else {
            let idx = self.permission_selection.min(self.pending_permissions.len() - 1);
            self.pending_permissions.get(idx)
        }
    }

    /// Get the selected port if any.
    #[must_use]
    pub fn selected_port(&self) -> Option<&DetectedPort> {
        if self.detected_ports.is_empty() {
            None
        } else {
            let idx = self.port_selection.min(self.detected_ports.len() - 1);
            self.detected_ports.get(idx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::channel::create_channel_pair;
    use uuid::Uuid;

    fn create_test_app() -> (TuiApp, crate::control::ProxyChannels) {
        let (proxy_channels, tui_channels) = create_channel_pair();
        let (_, shutdown_rx) = watch::channel(false);
        let app = TuiApp::new(tui_channels, shutdown_rx);
        (app, proxy_channels)
    }

    #[test]
    fn test_focus_cycle() {
        let (mut app, _proxy) = create_test_app();

        assert_eq!(app.focus(), FocusPanel::Permissions);
        app.focus_next();
        assert_eq!(app.focus(), FocusPanel::Ports);
        app.focus_next();
        assert_eq!(app.focus(), FocusPanel::Logs);
        app.focus_next();
        assert_eq!(app.focus(), FocusPanel::Permissions);

        app.focus_prev();
        assert_eq!(app.focus(), FocusPanel::Logs);
    }

    #[test]
    fn test_selection_bounds() {
        let (mut app, _proxy) = create_test_app();

        app.select_down();
        assert_eq!(app.permission_selection(), 0);
        app.select_up();
        assert_eq!(app.permission_selection(), 0);
    }

    #[tokio::test]
    async fn test_process_permission_request() {
        let (mut app, proxy) = create_test_app();

        let msg = ProxyToTui::PermissionRequest {
            id: Uuid::new_v4(),
            domain: "example.com".to_string(),
            port: 443,
            timestamp: Utc::now(),
        };

        proxy.send(msg).await.unwrap();

        assert!(app.try_process_message());
        assert_eq!(app.pending_permissions().len(), 1);
        assert_eq!(app.pending_permissions()[0].domain, "example.com");
    }

    #[tokio::test]
    async fn test_process_log_event() {
        let (mut app, proxy) = create_test_app();

        let msg = ProxyToTui::LogEvent {
            level: LogLevel::Info,
            category: EventCategory::Network,
            message: "Test message".to_string(),
            timestamp: Utc::now(),
        };

        proxy.send(msg).await.unwrap();

        assert!(app.try_process_message());
        assert_eq!(app.logs().len(), 1);
        assert_eq!(app.logs()[0].message, "Test message");
    }

    #[test]
    fn test_quit_flag() {
        let (mut app, _proxy) = create_test_app();

        assert!(!app.should_quit());
        app.quit();
        assert!(app.should_quit());
    }

    #[test]
    fn test_add_log() {
        let (mut app, _proxy) = create_test_app();

        app.add_log(LogLevel::Info, EventCategory::System, "Test".to_string());
        assert_eq!(app.logs().len(), 1);

        for i in 0..MAX_LOG_ENTRIES + 10 {
            app.add_log(LogLevel::Debug, EventCategory::System, format!("Log {}", i));
        }
        assert_eq!(app.logs().len(), MAX_LOG_ENTRIES);
    }
}