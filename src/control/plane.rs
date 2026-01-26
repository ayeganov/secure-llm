//! Control plane coordinator.
//!
//! The `ControlPlane` coordinates between the proxy, port monitor, and TUI.
//! It receives decisions from the TUI and applies them to pending connections
//! via the `ConnectionHoldManager`.
//!
//! # Responsibilities
//!
//! - Listen for TUI decisions and apply them
//! - Forward proxy events (permission requests) to TUI
//! - Manage "Always Allow/Block" persistence
//! - Handle graceful shutdown

use super::protocol::{Decision, ProxyToTui, TuiToProxy};
use crate::config::ConfigLoader;
use crate::proxy::hold::{ConnectionDecision, ConnectionHoldManager};
use crate::proxy::policy::PolicyEngine;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

/// The control plane coordinator.
///
/// Runs as a separate task, processing TUI decisions and applying them
/// to the proxy's hold manager. Supports both in-process channel-based
/// communication and socket-based IPC for subprocess TUI.
pub struct ControlPlane {
    /// Sender for messages to TUI.
    tui_tx: mpsc::Sender<ProxyToTui>,
    /// Receiver for messages from TUI.
    tui_rx: mpsc::Receiver<TuiToProxy>,
    /// Receiver for messages from proxy (permission requests, etc.).
    proxy_rx: mpsc::Receiver<ProxyToTui>,
    /// Reference to the connection hold manager.
    hold_manager: Arc<ConnectionHoldManager>,
    /// Reference to the policy engine (for "Always" decisions).
    policy: Arc<PolicyEngine>,
    /// Config loader for persisting decisions.
    config_loader: Option<ConfigLoader>,
    /// Shutdown signal receiver.
    shutdown_rx: watch::Receiver<bool>,
}

impl ControlPlane {
    /// Create a new control plane with socket-based TUI communication.
    ///
    /// # Arguments
    ///
    /// * `tui_tx` - Sender for messages to TUI (from socket accept).
    /// * `tui_rx` - Receiver for messages from TUI (from socket accept).
    /// * `proxy_rx` - Receiver for messages from proxy.
    /// * `hold_manager` - The proxy's connection hold manager.
    /// * `policy` - The proxy's policy engine.
    /// * `shutdown_rx` - Shutdown signal receiver.
    pub fn new_with_socket(
        tui_tx: mpsc::Sender<ProxyToTui>,
        tui_rx: mpsc::Receiver<TuiToProxy>,
        proxy_rx: mpsc::Receiver<ProxyToTui>,
        hold_manager: Arc<ConnectionHoldManager>,
        policy: Arc<PolicyEngine>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        Self {
            tui_tx,
            tui_rx,
            proxy_rx,
            hold_manager,
            policy,
            config_loader: None,
            shutdown_rx,
        }
    }

    /// Set a config loader for persisting "Always Allow/Block" decisions.
    pub fn with_config_loader(mut self, loader: ConfigLoader) -> Self {
        self.config_loader = Some(loader);
        self
    }

    /// Run the control plane event loop.
    ///
    /// Processes messages from both the proxy and TUI until shutdown is signaled
    /// or channels close.
    pub async fn run(mut self) {
        info!("Control plane started (socket-based)");

        loop {
            tokio::select! {
                // Messages from TUI (decisions)
                msg = self.tui_rx.recv() => {
                    match msg {
                        Some(msg) => self.handle_tui_message(msg).await,
                        None => {
                            // TUI channel closed
                            info!("TUI channel closed, control plane stopping");
                            break;
                        }
                    }
                }
                // Messages from proxy (permission requests, etc.)
                msg = self.proxy_rx.recv() => {
                    match msg {
                        Some(msg) => self.handle_proxy_message(msg).await,
                        None => {
                            // Proxy channel closed
                            info!("Proxy channel closed, control plane stopping");
                            break;
                        }
                    }
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("Control plane received shutdown signal");
                        // Send shutdown to TUI
                        let _ = self.tui_tx.send(ProxyToTui::Shutdown).await;
                        break;
                    }
                }
            }
        }

        info!("Control plane stopped");
    }

    /// Handle a message from the proxy (forward to TUI).
    async fn handle_proxy_message(&mut self, msg: ProxyToTui) {
        // Forward message to TUI
        if let Err(e) = self.tui_tx.send(msg).await {
            warn!("Failed to send message to TUI: {:?}", e);
        }
    }

    /// Handle a message from the TUI.
    async fn handle_tui_message(&mut self, msg: TuiToProxy) {
        match msg {
            TuiToProxy::PermissionDecision { id, decision, persist } => {
                self.handle_permission_decision(id, decision, persist).await;
            }
            TuiToProxy::PortDecision { id, bridge, host_port } => {
                self.handle_port_decision(id, bridge, host_port).await;
            }
            TuiToProxy::TuiShutdown => {
                info!("TUI signaled shutdown");
                // Don't break here - let the proxy continue in headless mode
            }
        }
    }

    /// Handle a permission decision from the TUI.
    async fn handle_permission_decision(
        &mut self,
        id: uuid::Uuid,
        decision: Decision,
        persist: bool,
    ) {
        // Get the domain from pending list (if still there)
        let domain = self.hold_manager
            .list_pending()
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.domain.clone());

        let conn_decision = match decision {
            Decision::Allow => ConnectionDecision::Allow,
            Decision::Block => ConnectionDecision::Block,
        };

        // Apply the decision to the hold manager
        match self.hold_manager.decide(id, conn_decision) {
            Ok(()) => {
                debug!("Applied decision {:?} for connection {}", decision, id);

                // Handle persistence (Always Allow/Block)
                if persist
                    && let Some(ref domain) = domain {
                        self.persist_decision(domain, decision).await;
                    }

                // Record session decision in policy engine
                if let Some(ref domain) = domain {
                    let allow = matches!(decision, Decision::Allow);
                    self.policy.record_decision(domain, allow);
                }
            }
            Err(e) => {
                warn!("Failed to apply decision for {}: {}", id, e);
            }
        }
    }

    /// Persist an "Always Allow/Block" decision.
    async fn persist_decision(&self, domain: &str, decision: Decision) {
        if let Some(ref loader) = self.config_loader {
            match decision {
                Decision::Allow => {
                    if let Err(e) = loader.save_to_allowlist(domain) {
                        warn!("Failed to persist allow for {}: {}", domain, e);
                    } else {
                        info!("Persisted 'Always Allow' for {}", domain);
                    }
                }
                Decision::Block => {
                    // TODO: Implement save_to_blocklist in ConfigLoader
                    // For now, just record in session policy (already done in handle_permission_decision)
                    info!("'Always Block' for {} recorded for session (persistent blocklist not yet implemented)", domain);
                }
            }
        } else {
            warn!("Cannot persist decision: no config loader available");
        }
    }

    /// Handle a port forwarding decision from the TUI.
    async fn handle_port_decision(
        &self,
        id: uuid::Uuid,
        bridge: bool,
        host_port: Option<u16>,
    ) {
        // Port forwarding will be implemented in Phase 5
        // For now, just log the decision
        if bridge {
            info!(
                "Port {} requested bridging to host port {:?}",
                id,
                host_port.unwrap_or(0)
            );
        } else {
            debug!("Port {} bridging declined", id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;
    use std::time::Duration;

    fn create_test_setup() -> (
        ControlPlane,
        mpsc::Sender<ProxyToTui>,
        mpsc::Receiver<ProxyToTui>,
        mpsc::Sender<TuiToProxy>,
    ) {
        let (proxy_to_ctrl_tx, proxy_to_ctrl_rx) = mpsc::channel(64);
        let (ctrl_to_tui_tx, ctrl_to_tui_rx) = mpsc::channel(64);
        let (tui_to_ctrl_tx, tui_to_ctrl_rx) = mpsc::channel(64);

        let hold_manager = Arc::new(ConnectionHoldManager::new(Duration::from_secs(30)));
        let network_config = NetworkConfig::default();
        let policy = Arc::new(PolicyEngine::from_config(&network_config, &[]));
        let (_, shutdown_rx) = watch::channel(false);

        let plane = ControlPlane::new_with_socket(
            ctrl_to_tui_tx,
            tui_to_ctrl_rx,
            proxy_to_ctrl_rx,
            hold_manager,
            policy,
            shutdown_rx,
        );

        (plane, proxy_to_ctrl_tx, ctrl_to_tui_rx, tui_to_ctrl_tx)
    }

    #[tokio::test]
    async fn test_permission_decision_allow() {
        let (mut plane, _proxy_tx, _tui_rx, tui_tx) = create_test_setup();

        // Park a connection
        let (id, _rx) = plane.hold_manager.park("example.com".to_string(), 443);

        // Simulate TUI decision
        let msg = TuiToProxy::PermissionDecision {
            id,
            decision: Decision::Allow,
            persist: false,
        };

        plane.handle_tui_message(msg).await;

        // Connection should be removed from pending
        assert_eq!(plane.hold_manager.pending_count(), 0);

        drop(tui_tx);
    }

    #[tokio::test]
    async fn test_permission_decision_block() {
        let (mut plane, _proxy_tx, _tui_rx, tui_tx) = create_test_setup();

        // Park a connection
        let (id, _rx) = plane.hold_manager.park("evil.com".to_string(), 443);

        // Simulate TUI decision
        let msg = TuiToProxy::PermissionDecision {
            id,
            decision: Decision::Block,
            persist: false,
        };

        plane.handle_tui_message(msg).await;

        // Connection should be removed from pending
        assert_eq!(plane.hold_manager.pending_count(), 0);

        drop(tui_tx);
    }

    #[tokio::test]
    async fn test_tui_shutdown_message() {
        let (mut plane, _proxy_tx, _tui_rx, tui_tx) = create_test_setup();

        // Simulate TUI shutdown
        let msg = TuiToProxy::TuiShutdown;
        plane.handle_tui_message(msg).await;

        // Control plane should continue (not panic)
        // The actual shutdown happens when channels close

        drop(tui_tx);
    }

    #[tokio::test]
    async fn test_proxy_message_forwarding() {
        let (_plane, proxy_tx, _tui_rx, _tui_tx) = create_test_setup();

        // Send a permission request from proxy
        let msg = ProxyToTui::PermissionRequest {
            id: uuid::Uuid::new_v4(),
            domain: "test.example.com".to_string(),
            port: 443,
            timestamp: chrono::Utc::now(),
        };

        proxy_tx.send(msg.clone()).await.unwrap();

        // Note: In a real test we'd need to run the control plane loop
        // For now, just verify the channels work
        drop(proxy_tx);
    }
}
