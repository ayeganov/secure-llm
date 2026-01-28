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
//! - Handle port detection events and bridging
//! - Handle graceful shutdown

use super::protocol::{Decision, ProxyToTui, TuiToProxy};
use crate::config::ConfigLoader;
use crate::portmon::{PortBridgeManager, PortEvent, PortState};
use crate::proxy::hold::{ConnectionDecision, ConnectionHoldManager};
use crate::proxy::policy::PolicyEngine;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Pending port information for bridging decisions.
struct PendingPort {
    /// The detected port number.
    port: u16,
}

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
    /// Port bridge manager (optional, for port bridging).
    bridge_manager: Option<Arc<Mutex<PortBridgeManager>>>,
    /// Receiver for port events from detector.
    port_event_rx: Option<mpsc::Receiver<PortEvent>>,
    /// Map from UUID to pending port info (for bridging decisions).
    pending_ports: HashMap<Uuid, PendingPort>,
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
            bridge_manager: None,
            port_event_rx: None,
            pending_ports: HashMap::new(),
            shutdown_rx,
        }
    }

    /// Set a config loader for persisting "Always Allow/Block" decisions.
    pub fn with_config_loader(mut self, loader: ConfigLoader) -> Self {
        self.config_loader = Some(loader);
        self
    }

    /// Set a port bridge manager for handling port bridging.
    pub fn with_bridge_manager(mut self, manager: Arc<Mutex<PortBridgeManager>>) -> Self {
        self.bridge_manager = Some(manager);
        self
    }

    /// Set a receiver for port events from the detector.
    pub fn with_port_events(mut self, rx: mpsc::Receiver<PortEvent>) -> Self {
        self.port_event_rx = Some(rx);
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
                // Port events from detector (if configured)
                event = async {
                    match &mut self.port_event_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(event) = event {
                        self.handle_port_event(event).await;
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
            TuiToProxy::StopBridge { id } => {
                self.handle_stop_bridge(id).await;
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
                    if let Err(e) = loader.save_to_blocklist(domain) {
                        warn!("Failed to persist block for {}: {}", domain, e);
                    } else {
                        info!("Persisted 'Always Block' for {}", domain);
                    }
                }
            }
        } else {
            warn!("Cannot persist decision: no config loader available");
        }
    }

    /// Handle a port forwarding decision from the TUI.
    async fn handle_port_decision(
        &mut self,
        id: Uuid,
        bridge: bool,
        host_port: Option<u16>,
    ) {
        if !bridge {
            debug!("Port {} bridging declined", id);
            return;
        }

        // Get the pending port info
        let pending = match self.pending_ports.get(&id) {
            Some(p) => p,
            None => {
                warn!("Port decision for unknown port ID: {}", id);
                return;
            }
        };

        let container_port = pending.port;
        let host_port = host_port.unwrap_or(container_port);

        // Try to start the bridge
        if let Some(ref manager) = self.bridge_manager {
            let mut mgr = manager.lock().await;
            match mgr.start_bridge(host_port, container_port).await {
                Ok(()) => {
                    info!(
                        "Started port bridge: host:{} -> container:{}",
                        host_port, container_port
                    );
                    // Send success notification to TUI
                    let _ = self
                        .tui_tx
                        .send(ProxyToTui::PortBridgeStarted {
                            id,
                            host_port,
                            container_port,
                        })
                        .await;
                }
                Err(e) => {
                    warn!(
                        "Failed to start port bridge {}:{}: {}",
                        host_port, container_port, e
                    );
                }
            }
        } else {
            warn!("Cannot bridge port: no bridge manager available");
        }
    }

    /// Handle a request to stop a port bridge.
    async fn handle_stop_bridge(&mut self, id: Uuid) {
        // Get the pending port info
        let pending = match self.pending_ports.get(&id) {
            Some(p) => p,
            None => {
                warn!("Stop bridge for unknown port ID: {}", id);
                return;
            }
        };

        let container_port = pending.port;

        // Try to stop the bridge
        if let Some(ref manager) = self.bridge_manager {
            let mut mgr = manager.lock().await;
            if let Some(host_port) = mgr.find_host_port_for_container(container_port) {
                mgr.stop_bridge(host_port).await;
                info!(
                    "Stopped port bridge: host:{} -> container:{}",
                    host_port, container_port
                );
                // Send notification to TUI
                let _ = self
                    .tui_tx
                    .send(ProxyToTui::PortBridgeStopped {
                        host_port,
                        container_port,
                        reason: "user request".to_string(),
                    })
                    .await;
            } else {
                debug!("Port {} is not currently bridged", container_port);
            }
        } else {
            warn!("Cannot stop bridge: no bridge manager available");
        }
    }

    /// Handle a port event from the detector.
    async fn handle_port_event(&mut self, event: PortEvent) {
        match event.state {
            PortState::New => {
                let id = Uuid::new_v4();
                let port_info = &event.port;

                // Store pending port info
                self.pending_ports.insert(
                    id,
                    PendingPort {
                        port: port_info.port,
                    },
                );

                // Notify TUI
                let _ = self
                    .tui_tx
                    .send(ProxyToTui::PortDetected {
                        id,
                        port: port_info.port,
                        local_addr: port_info.local_addr.to_string(),
                        process_name: port_info.process_name.clone(),
                        timestamp: Utc::now(),
                    })
                    .await;

                info!(
                    "Detected new port {} ({})",
                    port_info.port,
                    port_info.process_name.as_deref().unwrap_or("unknown")
                );
            }
            PortState::Closed => {
                let port = event.port.port;

                // Find and remove the pending port entry
                let id = self
                    .pending_ports
                    .iter()
                    .find(|(_, p)| p.port == port)
                    .map(|(id, _)| *id);

                if let Some(id) = id {
                    self.pending_ports.remove(&id);

                    // Notify TUI
                    let _ = self
                        .tui_tx
                        .send(ProxyToTui::PortClosed { id, port })
                        .await;
                }

                // Stop any bridge for this port
                if let Some(ref manager) = self.bridge_manager {
                    let mut mgr = manager.lock().await;
                    if let Some(host_port) = mgr.find_host_port_for_container(port) {
                        mgr.stop_bridge(host_port).await;
                        let _ = self
                            .tui_tx
                            .send(ProxyToTui::PortBridgeStopped {
                                host_port,
                                container_port: port,
                                reason: "app closed".to_string(),
                            })
                            .await;
                    }
                }

                debug!("Port {} closed", port);
            }
            PortState::Existing => {
                // No action needed for existing ports
            }
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
