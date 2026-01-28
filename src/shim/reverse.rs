//! Reverse shim daemon for dynamic port bridging.
//!
//! This module provides a daemon that runs inside the sandbox, listening on
//! Unix sockets for incoming connections from the host. Unlike the egress shim
//! which forwards outbound traffic, this handles inbound connections to
//! applications running in the sandbox.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────── Sandbox ────────────────────────┐
//! │                                                     │
//! │  ┌─────────┐    127.0.0.1:P    ┌──────────────────┐│
//! │  │  App    │◄──────────────────│  ReverseShim     ││
//! │  │(node,..)│                   │  LISTENS on:     ││
//! │  └─────────┘                   │  - control.sock  ││
//! │                                │  - 0.sock...7.sock│
//! │                                └──────────┬───────┘│
//! │  /tmp/portbridge/                         │        │
//! │    control.sock ──────────────────────────┼────────┼──┐
//! │    0.sock ────────────────────────────────┼────────┼──┤
//! └───────────────────────────────────────────┼────────┘  │
//!                                                         │
//! ┌──────────────────── Host ─────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────┐  │
//! │  │          Port Bridge Manager                    │◄─┘
//! │  │  (CONNECTS to sockets as client)                │
//! │  │  - Connects to control.sock to send commands    │
//! │  │  - Creates TCP listener on host:port            │
//! │  │  - On TCP accept: connects to slot N.sock       │
//! │  └─────────────────────────────────────────────────┘
//! └─────────────────────────────────────────────────────────
//! ```
//!
//! # Control Protocol
//!
//! The control socket accepts newline-delimited JSON commands:
//!
//! - `{"type":"activate","slot":0,"port":3000}` - Activate slot for port
//! - `{"type":"deactivate","slot":0}` - Deactivate slot
//! - `{"type":"status"}` - Query current status
//!
//! Responses are also newline-delimited JSON:
//!
//! - `{"type":"ok"}` - Success
//! - `{"type":"error","message":"..."}` - Failure
//! - `{"type":"status","slots":[...]}` - Status response

use serde::{Deserialize, Serialize};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::{watch, Mutex};

/// Default maximum number of port bridge slots.
pub const DEFAULT_MAX_SLOTS: u8 = 8;

/// Error type for reverse shim operations.
#[derive(Debug, thiserror::Error)]
pub enum ReverseShimError {
    /// Failed to create Unix listener.
    #[error("Failed to create Unix listener at {path}: {source}")]
    UnixBind {
        /// The socket path.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Failed to connect to target port.
    #[error("Failed to connect to 127.0.0.1:{port}: {source}")]
    TcpConnect {
        /// The target port.
        port: u16,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// I/O error during data transfer.
    #[error("I/O error during copy: {0}")]
    Copy(#[source] io::Error),
}

/// Control protocol request messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ControlRequest {
    /// Activate a slot for forwarding to a specific port.
    Activate {
        /// The slot index.
        slot: u8,
        /// The target port.
        port: u16,
    },
    /// Deactivate a slot.
    Deactivate {
        /// The slot index.
        slot: u8,
    },
    /// Query status of all slots.
    Status,
}

/// Control protocol response messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ControlResponse {
    /// Operation succeeded.
    Ok,
    /// Operation failed.
    Error {
        /// The error message.
        message: String,
    },
    /// Status response with slot information.
    Status {
        /// Information about each slot.
        slots: Vec<SlotInfo>,
    },
}

/// Information about a single slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotInfo {
    /// Slot index.
    pub slot: u8,
    /// Whether the slot is active.
    pub active: bool,
    /// Target port if active.
    pub port: Option<u16>,
}

/// State of a single slot.
#[derive(Debug)]
enum SlotState {
    /// Slot is free and listening for connections but not forwarding.
    Free,
    /// Slot is active and forwarding to a specific port.
    Active { target_port: u16 },
}

/// Shared state for a slot.
struct SlotContext {
    state: SlotState,
}

/// The reverse shim daemon.
pub struct ReverseShimDaemon {
    /// Directory for sockets.
    bridge_dir: PathBuf,
    /// Maximum slots.
    max_slots: u8,
    /// Slot contexts.
    slots: Vec<Arc<Mutex<SlotContext>>>,
    /// Shutdown receiver.
    shutdown_rx: watch::Receiver<bool>,
}

impl ReverseShimDaemon {
    /// Create a new reverse shim daemon.
    ///
    /// # Arguments
    ///
    /// * `bridge_dir` - Directory for Unix sockets (e.g., /tmp/portbridge)
    /// * `max_slots` - Maximum number of concurrent port bridges
    /// * `shutdown_rx` - Channel to receive shutdown signal
    pub fn new(
        bridge_dir: PathBuf,
        max_slots: u8,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        let slots = (0..max_slots)
            .map(|_| {
                Arc::new(Mutex::new(SlotContext {
                    state: SlotState::Free,
                }))
            })
            .collect();

        Self {
            bridge_dir,
            max_slots,
            slots,
            shutdown_rx,
        }
    }

    /// Run the reverse shim daemon.
    ///
    /// This starts listeners for the control socket and all slot sockets,
    /// then processes incoming connections until shutdown.
    pub async fn run(self) -> Result<(), ReverseShimError> {
        // Create control socket listener
        let control_path = self.bridge_dir.join("control.sock");
        let control_listener = UnixListener::bind(&control_path).map_err(|e| {
            ReverseShimError::UnixBind {
                path: control_path.display().to_string(),
                source: e,
            }
        })?;

        // Create slot socket listeners
        let mut slot_listeners = Vec::with_capacity(self.max_slots as usize);
        for i in 0..self.max_slots {
            let slot_path = self.bridge_dir.join(format!("{}.sock", i));
            let listener = UnixListener::bind(&slot_path).map_err(|e| {
                ReverseShimError::UnixBind {
                    path: slot_path.display().to_string(),
                    source: e,
                }
            })?;
            slot_listeners.push(listener);
        }

        // Spawn control handler
        let slots_for_control = self.slots.clone();
        let max_slots = self.max_slots;
        let mut control_shutdown = self.shutdown_rx.clone();

        let control_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = control_listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let slots = slots_for_control.clone();
                                tokio::spawn(async move {
                                    handle_control_connection(stream, slots, max_slots).await;
                                });
                            }
                            Err(e) => {
                                tracing::debug!("Control accept error: {}", e);
                            }
                        }
                    }
                    _ = control_shutdown.changed() => {
                        break;
                    }
                }
            }
        });

        // Spawn slot handlers
        let mut slot_handles = Vec::new();
        for (i, listener) in slot_listeners.into_iter().enumerate() {
            let slot_ctx = self.slots[i].clone();
            let mut slot_shutdown = self.shutdown_rx.clone();

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok((stream, _)) => {
                                    let ctx = slot_ctx.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_slot_connection(stream, ctx).await {
                                            // Log at debug level - connection refused is normal
                                            // when app isn't listening
                                            tracing::debug!("Slot connection error: {}", e);
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::debug!("Slot accept error: {}", e);
                                }
                            }
                        }
                        _ = slot_shutdown.changed() => {
                            break;
                        }
                    }
                }
            });
            slot_handles.push(handle);
        }

        // Wait for shutdown
        let mut shutdown = self.shutdown_rx.clone();
        let _ = shutdown.changed().await;

        // Abort all tasks
        control_handle.abort();
        for handle in slot_handles {
            handle.abort();
        }

        Ok(())
    }
}

/// Handle a control connection.
async fn handle_control_connection(
    stream: UnixStream,
    slots: Vec<Arc<Mutex<SlotContext>>>,
    max_slots: u8,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                let response = match serde_json::from_str::<ControlRequest>(line.trim()) {
                    Ok(request) => process_control_request(request, &slots, max_slots).await,
                    Err(e) => ControlResponse::Error {
                        message: format!("Invalid JSON: {}", e),
                    },
                };

                let mut response_json = serde_json::to_string(&response)
                    .unwrap_or_else(|_| r#"{"type":"error","message":"Serialization failed"}"#.to_string());
                response_json.push('\n');

                if writer.write_all(response_json.as_bytes()).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Process a control request.
async fn process_control_request(
    request: ControlRequest,
    slots: &[Arc<Mutex<SlotContext>>],
    max_slots: u8,
) -> ControlResponse {
    match request {
        ControlRequest::Activate { slot, port } => {
            if slot >= max_slots {
                return ControlResponse::Error {
                    message: format!("Invalid slot {} (max: {})", slot, max_slots - 1),
                };
            }

            let mut ctx = slots[slot as usize].lock().await;
            match &ctx.state {
                SlotState::Active { target_port } => {
                    ControlResponse::Error {
                        message: format!("Slot {} already active for port {}", slot, target_port),
                    }
                }
                SlotState::Free => {
                    ctx.state = SlotState::Active { target_port: port };
                    ControlResponse::Ok
                }
            }
        }

        ControlRequest::Deactivate { slot } => {
            if slot >= max_slots {
                return ControlResponse::Error {
                    message: format!("Invalid slot {} (max: {})", slot, max_slots - 1),
                };
            }

            let mut ctx = slots[slot as usize].lock().await;
            match &ctx.state {
                SlotState::Free => {
                    ControlResponse::Error {
                        message: format!("Slot {} is not active", slot),
                    }
                }
                SlotState::Active { .. } => {
                    ctx.state = SlotState::Free;
                    ControlResponse::Ok
                }
            }
        }

        ControlRequest::Status => {
            let mut slot_infos = Vec::with_capacity(slots.len());
            for (i, slot) in slots.iter().enumerate() {
                let ctx = slot.lock().await;
                let (active, port) = match &ctx.state {
                    SlotState::Free => (false, None),
                    SlotState::Active { target_port } => (true, Some(*target_port)),
                };
                slot_infos.push(SlotInfo {
                    slot: i as u8,
                    active,
                    port,
                });
            }
            ControlResponse::Status { slots: slot_infos }
        }
    }
}

/// Handle a data connection on a slot socket.
async fn handle_slot_connection(
    unix_stream: UnixStream,
    slot_ctx: Arc<Mutex<SlotContext>>,
) -> Result<(), ReverseShimError> {
    // Check if slot is active and get target port
    let target_port = {
        let ctx = slot_ctx.lock().await;
        match &ctx.state {
            SlotState::Free => {
                // Slot not active - just close the connection
                return Ok(());
            }
            SlotState::Active { target_port } => *target_port,
        }
    };

    // Connect to the target application
    let target_addr: SocketAddr = format!("127.0.0.1:{}", target_port)
        .parse()
        .expect("valid socket addr");

    let tcp_stream = TcpStream::connect(target_addr)
        .await
        .map_err(|e| ReverseShimError::TcpConnect {
            port: target_port,
            source: e,
        })?;

    // Bidirectionally copy data
    let (unix_read, unix_write) = unix_stream.into_split();
    let (tcp_read, tcp_write) = tcp_stream.into_split();

    let mut unix_joined = tokio::io::join(unix_read, unix_write);
    let mut tcp_joined = tokio::io::join(tcp_read, tcp_write);

    let copy_result = tokio::io::copy_bidirectional(&mut unix_joined, &mut tcp_joined).await;

    // Handle result - connection resets are normal
    match copy_result {
        Ok(_) => Ok(()),
        Err(e) => {
            let kind = e.kind();
            if kind == io::ErrorKind::ConnectionReset
                || kind == io::ErrorKind::BrokenPipe
                || kind == io::ErrorKind::UnexpectedEof
            {
                Ok(())
            } else {
                Err(ReverseShimError::Copy(e))
            }
        }
    }
}

/// Run the reverse shim daemon.
///
/// This is the main entry point for the `internal-reverse-shim` command.
///
/// # Arguments
///
/// * `bridge_dir` - Path to the port bridge socket directory
/// * `max_slots` - Maximum number of concurrent bridges
pub async fn run(bridge_dir: &Path, max_slots: u8) -> Result<(), ReverseShimError> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Handle SIGTERM/SIGINT for graceful shutdown
    let shutdown_tx_signal = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx_signal.send(true);
    });

    let daemon = ReverseShimDaemon::new(bridge_dir.to_path_buf(), max_slots, shutdown_rx);
    daemon.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_request_serialize() {
        let activate = ControlRequest::Activate { slot: 0, port: 3000 };
        let json = serde_json::to_string(&activate).unwrap();
        assert!(json.contains("activate"));
        assert!(json.contains("3000"));

        let deactivate = ControlRequest::Deactivate { slot: 1 };
        let json = serde_json::to_string(&deactivate).unwrap();
        assert!(json.contains("deactivate"));
        assert!(json.contains("1"));

        let status = ControlRequest::Status;
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("status"));
    }

    #[test]
    fn test_control_request_deserialize() {
        let json = r#"{"type":"activate","slot":0,"port":3000}"#;
        let request: ControlRequest = serde_json::from_str(json).unwrap();
        match request {
            ControlRequest::Activate { slot, port } => {
                assert_eq!(slot, 0);
                assert_eq!(port, 3000);
            }
            _ => panic!("Expected Activate"),
        }

        let json = r#"{"type":"deactivate","slot":2}"#;
        let request: ControlRequest = serde_json::from_str(json).unwrap();
        match request {
            ControlRequest::Deactivate { slot } => {
                assert_eq!(slot, 2);
            }
            _ => panic!("Expected Deactivate"),
        }

        let json = r#"{"type":"status"}"#;
        let request: ControlRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(request, ControlRequest::Status));
    }

    #[test]
    fn test_control_response_serialize() {
        let ok = ControlResponse::Ok;
        let json = serde_json::to_string(&ok).unwrap();
        assert_eq!(json, r#"{"type":"ok"}"#);

        let error = ControlResponse::Error {
            message: "test error".to_string(),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("error"));
        assert!(json.contains("test error"));

        let status = ControlResponse::Status {
            slots: vec![
                SlotInfo { slot: 0, active: true, port: Some(3000) },
                SlotInfo { slot: 1, active: false, port: None },
            ],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("status"));
        assert!(json.contains("3000"));
    }

    #[tokio::test]
    async fn test_process_control_request_activate() {
        let slots: Vec<Arc<Mutex<SlotContext>>> = (0..2)
            .map(|_| Arc::new(Mutex::new(SlotContext { state: SlotState::Free })))
            .collect();

        // Activate slot 0
        let response = process_control_request(
            ControlRequest::Activate { slot: 0, port: 3000 },
            &slots,
            2,
        )
        .await;
        assert!(matches!(response, ControlResponse::Ok));

        // Verify slot is active
        let ctx = slots[0].lock().await;
        match &ctx.state {
            SlotState::Active { target_port } => assert_eq!(*target_port, 3000),
            _ => panic!("Expected Active state"),
        }
        drop(ctx);

        // Try to activate already active slot
        let response = process_control_request(
            ControlRequest::Activate { slot: 0, port: 4000 },
            &slots,
            2,
        )
        .await;
        assert!(matches!(response, ControlResponse::Error { .. }));

        // Invalid slot
        let response = process_control_request(
            ControlRequest::Activate { slot: 5, port: 3000 },
            &slots,
            2,
        )
        .await;
        assert!(matches!(response, ControlResponse::Error { .. }));
    }

    #[tokio::test]
    async fn test_process_control_request_deactivate() {
        let slots: Vec<Arc<Mutex<SlotContext>>> = (0..2)
            .map(|_| Arc::new(Mutex::new(SlotContext { state: SlotState::Free })))
            .collect();

        // Activate first
        let _ = process_control_request(
            ControlRequest::Activate { slot: 0, port: 3000 },
            &slots,
            2,
        )
        .await;

        // Deactivate
        let response = process_control_request(
            ControlRequest::Deactivate { slot: 0 },
            &slots,
            2,
        )
        .await;
        assert!(matches!(response, ControlResponse::Ok));

        // Verify slot is free
        let ctx = slots[0].lock().await;
        assert!(matches!(ctx.state, SlotState::Free));
        drop(ctx);

        // Try to deactivate already free slot
        let response = process_control_request(
            ControlRequest::Deactivate { slot: 0 },
            &slots,
            2,
        )
        .await;
        assert!(matches!(response, ControlResponse::Error { .. }));
    }

    #[tokio::test]
    async fn test_process_control_request_status() {
        let slots: Vec<Arc<Mutex<SlotContext>>> = (0..2)
            .map(|_| Arc::new(Mutex::new(SlotContext { state: SlotState::Free })))
            .collect();

        // Activate slot 0
        let _ = process_control_request(
            ControlRequest::Activate { slot: 0, port: 3000 },
            &slots,
            2,
        )
        .await;

        // Get status
        let response = process_control_request(ControlRequest::Status, &slots, 2).await;

        match response {
            ControlResponse::Status { slots: slot_infos } => {
                assert_eq!(slot_infos.len(), 2);
                assert!(slot_infos[0].active);
                assert_eq!(slot_infos[0].port, Some(3000));
                assert!(!slot_infos[1].active);
                assert_eq!(slot_infos[1].port, None);
            }
            _ => panic!("Expected Status response"),
        }
    }
}
