//! Port bridge manager for socket-based port forwarding.
//!
//! This module implements port bridging using Unix sockets instead of veth IPs.
//! It works with the reverse shim daemon inside the sandbox to forward TCP
//! connections through pre-allocated Unix sockets.
//!
//! # Architecture
//!
//! ```text
//! Host                              Sandbox
//! ────                              ───────
//! PortBridgeManager                 ReverseShimDaemon
//!   │                                 │
//!   ├─── CONNECTS to ─────────────────┼── control.sock (LISTENS)
//!   │    (sends activate cmd)         │
//!   │                                 │
//!   ├── TCP Listener (host:port)      │
//!   │      │                          │
//!   │      ▼ on accept                │
//!   └─── CONNECTS to ─────────────────┼── N.sock (LISTENS)
//!        (forwards data)              │     │
//!                                     │     ▼
//!                                     └── TCP Connect (127.0.0.1:port)
//! ```
//!
//! # Example
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use secure_llm::portmon::bridge::PortBridgeManager;
//! use std::path::PathBuf;
//!
//! let mut manager = PortBridgeManager::new(
//!     PathBuf::from("/tmp/secure-llm-xxx/portbridge"),
//!     8,
//! );
//!
//! // Connect to the reverse shim
//! manager.connect_control().await?;
//!
//! // Start a bridge
//! manager.start_bridge(3000, 3000).await?;
//!
//! // List active bridges
//! println!("Active bridges: {:?}", manager.list_bridges());
//! # Ok(())
//! # }
//! ```

use crate::shim::reverse::{ControlRequest, ControlResponse};
use crate::telemetry::{AuditEvent, AuditLogger};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::error::{PortMonError, PortMonResult};

/// Information about an active bridge.
#[derive(Debug, Clone)]
pub struct BridgeInfo {
    /// Host port being listened on.
    pub host_port: u16,
    /// Container port being forwarded to.
    pub container_port: u16,
    /// Slot index in use.
    pub slot: u8,
}

/// An active port bridge.
struct ActiveBridge {
    /// Host port.
    host_port: u16,
    /// Container port.
    container_port: u16,
    /// Slot index.
    slot: u8,
    /// Handle to the listener task.
    handle: tokio::task::JoinHandle<()>,
}

/// Port bridge manager (host-side).
///
/// Connects to Unix sockets as a client and creates TCP listeners on the host
/// to forward connections to the sandbox.
pub struct PortBridgeManager {
    /// Path to the portbridge directory.
    portbridge_dir: PathBuf,
    /// Control connection to the reverse shim.
    control_stream: Option<(
        BufReader<tokio::net::unix::OwnedReadHalf>,
        BufWriter<tokio::net::unix::OwnedWriteHalf>,
    )>,
    /// Active bridges (host_port -> bridge).
    bridges: HashMap<u16, ActiveBridge>,
    /// Free slot indices.
    free_slots: VecDeque<u8>,
    /// Shutdown sender.
    shutdown_tx: watch::Sender<bool>,
    /// Shutdown receiver template.
    shutdown_rx: watch::Receiver<bool>,
    /// Optional audit logger.
    audit: Option<Arc<AuditLogger>>,
}

impl PortBridgeManager {
    /// Create a new port bridge manager.
    ///
    /// # Arguments
    ///
    /// * `portbridge_dir` - Path to the portbridge socket directory
    /// * `max_slots` - Maximum number of concurrent bridges
    pub fn new(portbridge_dir: PathBuf, max_slots: u8) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let free_slots: VecDeque<u8> = (0..max_slots).collect();

        Self {
            portbridge_dir,
            control_stream: None,
            bridges: HashMap::new(),
            free_slots,
            shutdown_tx,
            shutdown_rx,
            audit: None,
        }
    }

    /// Set the audit logger for logging port bridge events.
    pub fn with_audit(mut self, audit: Arc<AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Connect to the control socket.
    ///
    /// This must be called before starting any bridges. Will retry up to 3 times
    /// with 500ms delay between attempts.
    pub async fn connect_control(&mut self) -> PortMonResult<()> {
        let control_path = self.portbridge_dir.join("control.sock");
        let mut last_error = None;

        for attempt in 1..=3 {
            match UnixStream::connect(&control_path).await {
                Ok(stream) => {
                    let (read, write) = stream.into_split();
                    self.control_stream = Some((
                        BufReader::new(read),
                        BufWriter::new(write),
                    ));
                    info!("Connected to reverse shim control socket");
                    return Ok(());
                }
                Err(e) => {
                    debug!(
                        "Control socket connect attempt {}/3 failed: {}",
                        attempt, e
                    );
                    last_error = Some(e);
                    if attempt < 3 {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }
        }

        Err(PortMonError::Io(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Failed to connect to control socket")
        })))
    }

    /// Check if connected to control socket.
    pub fn is_connected(&self) -> bool {
        self.control_stream.is_some()
    }

    /// Send a control request and wait for response.
    async fn send_control_request(
        &mut self,
        request: ControlRequest,
    ) -> PortMonResult<ControlResponse> {
        let (reader, writer) = self
            .control_stream
            .as_mut()
            .ok_or_else(|| PortMonError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "Not connected to control socket",
            )))?;

        // Serialize and send request
        let mut request_json = serde_json::to_string(&request)
            .map_err(|e| PortMonError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        request_json.push('\n');

        writer.write_all(request_json.as_bytes()).await?;
        writer.flush().await?;

        // Read response
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await?;

        let response: ControlResponse = serde_json::from_str(response_line.trim())
            .map_err(|e| PortMonError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;

        Ok(response)
    }

    /// Start a port bridge.
    ///
    /// # Arguments
    ///
    /// * `host_port` - Port to listen on (on the host)
    /// * `container_port` - Port to connect to (in the sandbox)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The host port is already being bridged
    /// - No free slots available
    /// - Control socket not connected
    /// - Control socket communication fails
    pub async fn start_bridge(
        &mut self,
        host_port: u16,
        container_port: u16,
    ) -> PortMonResult<()> {
        // Check for duplicate
        if self.bridges.contains_key(&host_port) {
            return Err(PortMonError::PortAlreadyForwarded(host_port));
        }

        // Get a free slot
        let slot = self.free_slots.pop_front().ok_or_else(|| {
            PortMonError::Io(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "No free port bridge slots available",
            ))
        })?;

        // Activate the slot on the reverse shim
        let response = self
            .send_control_request(ControlRequest::Activate {
                slot,
                port: container_port,
            })
            .await;

        match response {
            Ok(ControlResponse::Ok) => {}
            Ok(ControlResponse::Error { message }) => {
                // Return slot to pool
                self.free_slots.push_back(slot);
                return Err(PortMonError::Io(io::Error::other(message)));
            }
            Ok(ControlResponse::Status { .. }) => {
                self.free_slots.push_back(slot);
                return Err(PortMonError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected status response",
                )));
            }
            Err(e) => {
                self.free_slots.push_back(slot);
                return Err(e);
            }
        }

        // Create TCP listener on host
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", host_port)).await {
            Ok(l) => l,
            Err(e) => {
                // Deactivate the slot since we failed to bind
                let _ = self
                    .send_control_request(ControlRequest::Deactivate { slot })
                    .await;
                self.free_slots.push_back(slot);
                return Err(PortMonError::ListenFailed {
                    port: host_port,
                    source: e,
                });
            }
        };

        // Spawn the listener task
        let slot_socket_path = self.portbridge_dir.join(format!("{}.sock", slot));
        let mut shutdown_rx = self.shutdown_rx.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((tcp_stream, peer_addr)) => {
                                debug!(
                                    "Port bridge {}:{} connection from {}",
                                    host_port, container_port, peer_addr
                                );
                                let socket_path = slot_socket_path.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = bridge_connection(tcp_stream, socket_path).await {
                                        debug!("Bridge connection error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                debug!("Accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!(
                                "Port bridge {}:{} shutting down",
                                host_port, container_port
                            );
                            break;
                        }
                    }
                }
            }
        });

        // Store the bridge
        self.bridges.insert(
            host_port,
            ActiveBridge {
                host_port,
                container_port,
                slot,
                handle,
            },
        );

        // Log the port bridge event
        if let Some(ref audit) = self.audit {
            audit.log(AuditEvent::PortBridge {
                container_port,
                host_port,
            });
        }

        info!(
            "Started port bridge: 0.0.0.0:{} -> sandbox:{}",
            host_port, container_port
        );

        Ok(())
    }

    /// Stop a port bridge by host port.
    pub async fn stop_bridge(&mut self, host_port: u16) {
        if let Some(bridge) = self.bridges.remove(&host_port) {
            // Abort the listener task
            bridge.handle.abort();

            // Deactivate the slot
            if let Err(e) = self
                .send_control_request(ControlRequest::Deactivate { slot: bridge.slot })
                .await
            {
                warn!("Failed to deactivate slot {}: {}", bridge.slot, e);
            }

            // Return slot to pool
            self.free_slots.push_back(bridge.slot);

            info!("Stopped port bridge on host port {}", host_port);
        }
    }

    /// Stop a bridge by container port.
    ///
    /// Useful when an app closes its listening port.
    pub async fn stop_bridge_for_container_port(&mut self, container_port: u16) {
        // Find the bridge with this container port
        let host_port = self
            .bridges
            .iter()
            .find(|(_, b)| b.container_port == container_port)
            .map(|(hp, _)| *hp);

        if let Some(host_port) = host_port {
            self.stop_bridge(host_port).await;
        }
    }

    /// Shutdown all bridges.
    pub fn shutdown_all(&self) {
        let _ = self.shutdown_tx.send(true);
        info!("Shutting down all port bridges");
    }

    /// Get list of active bridges.
    pub fn list_bridges(&self) -> Vec<BridgeInfo> {
        self.bridges
            .values()
            .map(|b| BridgeInfo {
                host_port: b.host_port,
                container_port: b.container_port,
                slot: b.slot,
            })
            .collect()
    }

    /// Get the number of active bridges.
    pub fn bridge_count(&self) -> usize {
        self.bridges.len()
    }

    /// Get the number of available slots.
    pub fn available_slots(&self) -> usize {
        self.free_slots.len()
    }

    /// Check if a host port is being bridged.
    pub fn is_bridging(&self, host_port: u16) -> bool {
        self.bridges.contains_key(&host_port)
    }

    /// Find the host port for a container port if bridged.
    pub fn find_host_port_for_container(&self, container_port: u16) -> Option<u16> {
        self.bridges
            .iter()
            .find(|(_, b)| b.container_port == container_port)
            .map(|(hp, _)| *hp)
    }
}

/// Bridge a single TCP connection through a Unix socket.
async fn bridge_connection(tcp_stream: TcpStream, socket_path: PathBuf) -> io::Result<()> {
    // Connect to the slot socket
    let unix_stream = UnixStream::connect(&socket_path).await?;

    // Bidirectional copy
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
    let (mut unix_read, mut unix_write) = unix_stream.into_split();

    let tcp_to_unix = tokio::io::copy(&mut tcp_read, &mut unix_write);
    let unix_to_tcp = tokio::io::copy(&mut unix_read, &mut tcp_write);

    tokio::select! {
        result = tcp_to_unix => {
            if let Err(e) = result
                && e.kind() != io::ErrorKind::ConnectionReset
                && e.kind() != io::ErrorKind::BrokenPipe
                && e.kind() != io::ErrorKind::UnexpectedEof
            {
                return Err(e);
            }
        }
        result = unix_to_tcp => {
            if let Err(e) = result
                && e.kind() != io::ErrorKind::ConnectionReset
                && e.kind() != io::ErrorKind::BrokenPipe
                && e.kind() != io::ErrorKind::UnexpectedEof
            {
                return Err(e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_info() {
        let info = BridgeInfo {
            host_port: 3000,
            container_port: 3000,
            slot: 0,
        };
        assert_eq!(info.host_port, 3000);
        assert_eq!(info.container_port, 3000);
        assert_eq!(info.slot, 0);
    }

    #[test]
    fn test_manager_creation() {
        let manager = PortBridgeManager::new(PathBuf::from("/tmp/test"), 8);
        assert_eq!(manager.bridge_count(), 0);
        assert_eq!(manager.available_slots(), 8);
        assert!(!manager.is_connected());
    }

    #[test]
    fn test_free_slots_ordering() {
        let manager = PortBridgeManager::new(PathBuf::from("/tmp/test"), 4);
        let slots: Vec<u8> = manager.free_slots.iter().copied().collect();
        assert_eq!(slots, vec![0, 1, 2, 3]);
    }

    #[tokio::test]
    async fn test_start_bridge_not_connected() {
        let mut manager = PortBridgeManager::new(PathBuf::from("/tmp/test"), 8);
        let result = manager.start_bridge(3000, 3000).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_is_bridging() {
        let manager = PortBridgeManager::new(PathBuf::from("/tmp/test"), 8);
        assert!(!manager.is_bridging(3000));
    }

    #[test]
    fn test_list_bridges_empty() {
        let manager = PortBridgeManager::new(PathBuf::from("/tmp/test"), 8);
        assert!(manager.list_bridges().is_empty());
    }
}
