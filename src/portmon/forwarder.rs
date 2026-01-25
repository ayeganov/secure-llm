//! TCP port forwarding for sandbox ports.
//!
//! This module implements port bridging that makes ports listening inside the
//! sandbox accessible from the host. It handles:
//!
//! - Static port mappings (from `--publish` flag)
//! - Dynamic port bridging (from TUI approval in Phase 5)
//!
//! # Namespace Crossing
//!
//! The forwarder must cross network namespace boundaries:
//! - Listener socket is in the **host** namespace
//! - Target port is in the **sandbox** namespace
//!
//! We use the **veth IP approach**: connect to the sandbox's veth IP address
//! (e.g., `10.200.0.2:3000`) from the host. This works because we set up
//! routing in Phase 2.
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::portmon::forwarder::{PortForwardManager, ForwardConfig};
//! use std::net::Ipv4Addr;
//!
//! let mut manager = PortForwardManager::new(Ipv4Addr::new(10, 200, 0, 2));
//!
//! // Start a port forward
//! manager.start_forward(3000, 3000)?;  // host:3000 -> sandbox:3000
//!
//! // List active forwards
//! println!("Active forwards: {:?}", manager.list_forwards());
//!
//! // Shutdown all
//! manager.shutdown_all();
//! ```

use super::error::PortMonError;
use crate::telemetry::{AuditEvent, AuditLogger};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info};

/// Configuration for a port forward.
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Port to listen on (host side).
    pub host_port: u16,
    /// Port to connect to (sandbox side).
    pub container_port: u16,
    /// Sandbox IP address (veth address, e.g., 10.200.0.2).
    pub sandbox_ip: Ipv4Addr,
}

/// A running port forwarder.
pub struct PortForwarder {
    config: ForwardConfig,
    /// Shutdown signal.
    shutdown_rx: watch::Receiver<bool>,
}

impl PortForwarder {
    /// Create a new port forwarder.
    pub fn new(config: ForwardConfig, shutdown_rx: watch::Receiver<bool>) -> Self {
        Self {
            config,
            shutdown_rx,
        }
    }

    /// Run the port forwarder.
    ///
    /// Listens on the host port and forwards connections to the sandbox port.
    /// Returns when the shutdown signal is received or an unrecoverable error occurs.
    pub async fn run(self) -> Result<(), PortMonError> {
        let listen_addr = SocketAddr::from(([0, 0, 0, 0], self.config.host_port));
        let listener = TcpListener::bind(listen_addr).await.map_err(|e| {
            PortMonError::ListenFailed {
                port: self.config.host_port,
                source: e,
            }
        })?;

        info!(
            "Port forwarder: 0.0.0.0:{} -> {}:{}",
            self.config.host_port, self.config.sandbox_ip, self.config.container_port
        );

        let target_addr = SocketAddr::from((self.config.sandbox_ip, self.config.container_port));

        let mut shutdown_rx = self.shutdown_rx.clone();
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            debug!("Port forward connection from {}", peer_addr);
                            tokio::spawn(forward_connection(stream, target_addr));
                        }
                        Err(e) => {
                            debug!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!(
                            "Port forwarder {}:{} shutting down",
                            self.config.host_port,
                            self.config.container_port
                        );
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Forward a single connection.
async fn forward_connection(mut client: TcpStream, target: SocketAddr) {
    // Connect to sandbox
    let mut upstream = match TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(e) => {
            debug!("Failed to connect to {}: {}", target, e);
            // Try to send an error to the client before closing
            let _ = client.shutdown().await;
            return;
        }
    };

    // Bidirectional copy
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

    tokio::select! {
        result = client_to_upstream => {
            if let Err(e) = result {
                debug!("Client->upstream copy ended: {}", e);
            }
        }
        result = upstream_to_client => {
            if let Err(e) = result {
                debug!("Upstream->client copy ended: {}", e);
            }
        }
    }
}

/// Manager for multiple port forwarders.
///
/// Handles lifecycle management of port forwards including starting,
/// stopping, and listing active forwards.
pub struct PortForwardManager {
    /// Running forwarders (host_port -> handle).
    forwarders: HashMap<u16, tokio::task::JoinHandle<()>>,
    /// Shutdown sender (shared by all forwarders).
    shutdown_tx: watch::Sender<bool>,
    /// Shutdown receiver template.
    shutdown_rx: watch::Receiver<bool>,
    /// Sandbox IP address.
    sandbox_ip: Ipv4Addr,
    /// Optional audit logger.
    audit: Option<Arc<AuditLogger>>,
}

impl PortForwardManager {
    /// Create a new port forward manager.
    ///
    /// # Arguments
    ///
    /// * `sandbox_ip` - IP address of the sandbox's veth interface (e.g., 10.200.0.2)
    pub fn new(sandbox_ip: Ipv4Addr) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            forwarders: HashMap::new(),
            shutdown_tx,
            shutdown_rx,
            sandbox_ip,
            audit: None,
        }
    }

    /// Set the audit logger for logging port bridge events.
    pub fn with_audit(mut self, audit: Arc<AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Start a port forward.
    ///
    /// # Arguments
    ///
    /// * `host_port` - Port to listen on (on the host)
    /// * `container_port` - Port to connect to (in the sandbox)
    ///
    /// # Errors
    ///
    /// Returns error if the port is already being forwarded.
    pub fn start_forward(&mut self, host_port: u16, container_port: u16) -> Result<(), PortMonError> {
        if self.forwarders.contains_key(&host_port) {
            return Err(PortMonError::PortAlreadyForwarded(host_port));
        }

        let config = ForwardConfig {
            host_port,
            container_port,
            sandbox_ip: self.sandbox_ip,
        };

        let forwarder = PortForwarder::new(config, self.shutdown_rx.clone());
        let handle = tokio::spawn(async move {
            if let Err(e) = forwarder.run().await {
                error!("Port forwarder error: {}", e);
            }
        });

        self.forwarders.insert(host_port, handle);

        // Log the port bridge event
        if let Some(ref audit) = self.audit {
            audit.log(AuditEvent::PortBridge {
                container_port,
                host_port,
            });
        }

        info!(
            "Started port forward: 0.0.0.0:{} -> {}:{}",
            host_port, self.sandbox_ip, container_port
        );

        Ok(())
    }

    /// Stop a port forward.
    ///
    /// # Arguments
    ///
    /// * `host_port` - The host port to stop forwarding.
    pub fn stop_forward(&mut self, host_port: u16) {
        if let Some(handle) = self.forwarders.remove(&host_port) {
            handle.abort();
            info!("Stopped port forward on host port {}", host_port);
        }
    }

    /// Shutdown all forwarders.
    pub fn shutdown_all(&self) {
        let _ = self.shutdown_tx.send(true);
        info!("Shutting down all port forwarders");
    }

    /// Get list of active forwards (host ports).
    pub fn list_forwards(&self) -> Vec<u16> {
        self.forwarders.keys().copied().collect()
    }

    /// Get the number of active forwards.
    pub fn forward_count(&self) -> usize {
        self.forwarders.len()
    }

    /// Check if a port is being forwarded.
    pub fn is_forwarding(&self, host_port: u16) -> bool {
        self.forwarders.contains_key(&host_port)
    }

    /// Get the sandbox IP address.
    pub fn sandbox_ip(&self) -> Ipv4Addr {
        self.sandbox_ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_config_creation() {
        let config = ForwardConfig {
            host_port: 3000,
            container_port: 3000,
            sandbox_ip: Ipv4Addr::new(10, 200, 0, 2),
        };

        assert_eq!(config.host_port, 3000);
        assert_eq!(config.container_port, 3000);
        assert_eq!(config.sandbox_ip, Ipv4Addr::new(10, 200, 0, 2));
    }

    #[test]
    fn test_manager_creation() {
        let manager = PortForwardManager::new(Ipv4Addr::new(10, 200, 0, 2));
        assert_eq!(manager.forward_count(), 0);
        assert!(manager.list_forwards().is_empty());
        assert_eq!(manager.sandbox_ip(), Ipv4Addr::new(10, 200, 0, 2));
    }

    #[tokio::test]
    async fn test_start_forward_duplicate() {
        let mut manager = PortForwardManager::new(Ipv4Addr::new(10, 200, 0, 2));

        // First forward should succeed
        // Note: This will actually start listening, but will fail to connect to sandbox
        // which is fine for the test
        let result = manager.start_forward(13000, 3000);
        assert!(result.is_ok());

        // Second forward on same port should fail
        let result = manager.start_forward(13000, 3000);
        assert!(matches!(result, Err(PortMonError::PortAlreadyForwarded(13000))));

        // Clean up
        manager.stop_forward(13000);
    }

    #[tokio::test]
    async fn test_stop_forward() {
        let mut manager = PortForwardManager::new(Ipv4Addr::new(10, 200, 0, 2));

        manager.start_forward(13001, 3001).unwrap();
        assert_eq!(manager.forward_count(), 1);

        manager.stop_forward(13001);
        assert_eq!(manager.forward_count(), 0);

        // Stopping non-existent forward is a no-op
        manager.stop_forward(13001);
    }

    #[test]
    fn test_is_forwarding() {
        let manager = PortForwardManager::new(Ipv4Addr::new(10, 200, 0, 2));
        assert!(!manager.is_forwarding(3000));
    }

    #[test]
    fn test_list_forwards() {
        let manager = PortForwardManager::new(Ipv4Addr::new(10, 200, 0, 2));
        let ports = manager.list_forwards();
        assert!(ports.is_empty());
    }
}
