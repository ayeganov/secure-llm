//! Unix socket IPC transport for control plane communication.
//!
//! This module provides socket-based transport for communication between
//! the main process and the TUI subprocess running in a tmux sidecar pane.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────┐  Unix Socket  ┌──────────────────────────┐
//! │     Main Process         │←─────────────→│   TUI Subprocess         │
//! │  ┌──────────────────┐    │    bincode    │  ┌──────────────────┐    │
//! │  │  ControlSocket   │    │               │  │  ControlSocket   │    │
//! │  │  Server          │    │               │  │  Client          │    │
//! │  └──────────────────┘    │               │  └──────────────────┘    │
//! └──────────────────────────┘               └──────────────────────────┘
//! ```
//!
//! # Message Framing
//!
//! Messages use length-prefixed bincode:
//! ```text
//! [4 bytes: message length (big-endian u32)]
//! [N bytes: bincode-serialized message]
//! ```

use super::protocol::{ProxyToTui, TuiToProxy};
use std::io;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::Path;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Errors from socket operations.
#[derive(Debug, Error)]
pub enum SocketError {
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    /// Connection closed.
    #[error("Connection closed")]
    ConnectionClosed,
    /// Message too large.
    #[error("Message too large: {0} bytes (max {1})")]
    MessageTooLarge(usize, usize),
}

/// Maximum message size (16 MB should be plenty).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Result type for socket operations.
pub type SocketResult<T> = Result<T, SocketError>;

/// Server-side socket for the main process.
///
/// Listens for a single TUI connection and provides bidirectional
/// message passing.
pub struct ControlSocketServer {
    /// The Unix listener (std version, can be created outside tokio runtime).
    /// Option allows moving it out in accept() since we implement Drop.
    listener: Option<StdUnixListener>,
    /// Path to the socket file.
    socket_path: std::path::PathBuf,
}

impl ControlSocketServer {
    /// Create a new socket server at the given path.
    ///
    /// This will remove any existing socket file at the path.
    /// Note: This uses std's UnixListener so it can be called outside of
    /// a tokio runtime context.
    pub fn new<P: AsRef<Path>>(socket_path: P) -> SocketResult<Self> {
        let socket_path = socket_path.as_ref().to_path_buf();

        // Remove existing socket file if it exists
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)?;
        }

        // Use std's UnixListener which doesn't require tokio runtime
        let listener = StdUnixListener::bind(&socket_path)?;
        // Set non-blocking so we can convert to tokio later
        listener.set_nonblocking(true)?;
        info!("Control socket server listening on {:?}", socket_path);

        Ok(Self {
            listener: Some(listener),
            socket_path,
        })
    }

    /// Accept a single TUI connection.
    ///
    /// Returns channel handles for bidirectional communication.
    pub async fn accept(
        mut self,
    ) -> SocketResult<(
        mpsc::Sender<ProxyToTui>,
        mpsc::Receiver<TuiToProxy>,
    )> {
        // Take the listener out (consume it)
        let std_listener = self.listener.take()
            .ok_or_else(|| io::Error::other("listener already consumed"))?;

        // Convert std listener to tokio listener (requires tokio runtime)
        let listener = UnixListener::from_std(std_listener)?;
        let (stream, _addr) = listener.accept().await?;
        info!("TUI connected to control socket");

        let (proxy_tx, proxy_rx) = mpsc::channel::<ProxyToTui>(64);
        let (tui_tx, tui_rx) = mpsc::channel::<TuiToProxy>(64);

        // Split stream for reading and writing
        let (read_half, write_half) = stream.into_split();

        // Spawn reader task: reads TuiToProxy messages from socket, sends to channel
        tokio::spawn(async move {
            if let Err(e) = socket_reader(read_half, tui_tx).await
                && !matches!(e, SocketError::ConnectionClosed) {
                    error!("Socket reader error: {}", e);
                }
            debug!("Socket reader task finished");
        });

        // Spawn writer task: receives ProxyToTui messages from channel, writes to socket
        tokio::spawn(async move {
            if let Err(e) = socket_writer(write_half, proxy_rx).await
                && !matches!(e, SocketError::ConnectionClosed) {
                    error!("Socket writer error: {}", e);
                }
            debug!("Socket writer task finished");
        });

        Ok((proxy_tx, tui_rx))
    }

    /// Get the socket path.
    pub fn path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for ControlSocketServer {
    fn drop(&mut self) {
        // Clean up socket file
        if self.socket_path.exists()
            && let Err(e) = std::fs::remove_file(&self.socket_path) {
                warn!("Failed to remove socket file: {}", e);
            }
    }
}

/// Client-side socket for the TUI subprocess.
///
/// Connects to the main process socket and provides bidirectional
/// message passing.
pub struct ControlSocketClient {
    /// Channel sender for outgoing messages.
    tx: mpsc::Sender<TuiToProxy>,
    /// Channel receiver for incoming messages.
    rx: mpsc::Receiver<ProxyToTui>,
}

impl ControlSocketClient {
    /// Connect to the socket server at the given path.
    pub async fn connect<P: AsRef<Path>>(socket_path: P) -> SocketResult<Self> {
        let socket_path = socket_path.as_ref();
        let stream = UnixStream::connect(socket_path).await?;
        info!("Connected to control socket at {:?}", socket_path);

        let (tui_tx, tui_rx) = mpsc::channel::<TuiToProxy>(64);
        let (proxy_tx, proxy_rx) = mpsc::channel::<ProxyToTui>(64);

        // Split stream for reading and writing
        let (read_half, write_half) = stream.into_split();

        // Spawn reader task: reads ProxyToTui messages from socket, sends to channel
        tokio::spawn(async move {
            if let Err(e) = socket_reader_client(read_half, proxy_tx).await
                && !matches!(e, SocketError::ConnectionClosed) {
                    error!("Socket reader error: {}", e);
                }
            debug!("Client socket reader task finished");
        });

        // Spawn writer task: receives TuiToProxy messages from channel, writes to socket
        tokio::spawn(async move {
            if let Err(e) = socket_writer_client(write_half, tui_rx).await
                && !matches!(e, SocketError::ConnectionClosed) {
                    error!("Socket writer error: {}", e);
                }
            debug!("Client socket writer task finished");
        });

        Ok(Self { tx: tui_tx, rx: proxy_rx })
    }

    /// Send a message to the main process.
    pub async fn send(&self, msg: TuiToProxy) -> Result<(), TuiToProxy> {
        self.tx.send(msg).await.map_err(|e| e.0)
    }

    /// Try to receive a message from the main process without blocking.
    pub fn try_recv(&mut self) -> Option<ProxyToTui> {
        self.rx.try_recv().ok()
    }

    /// Receive a message from the main process, blocking until one is available.
    pub async fn recv(&mut self) -> Option<ProxyToTui> {
        self.rx.recv().await
    }
}

/// Read a length-prefixed message from the stream.
async fn read_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> SocketResult<Vec<u8>> {
    // Read length prefix (4 bytes, big-endian u32)
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(SocketError::ConnectionClosed);
        }
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(SocketError::MessageTooLarge(len, MAX_MESSAGE_SIZE));
    }

    // Read message body
    let mut buf = vec![0u8; len];
    match reader.read_exact(&mut buf).await {
        Ok(_) => Ok(buf),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Err(SocketError::ConnectionClosed)
        }
        Err(e) => Err(e.into()),
    }
}

/// Write a length-prefixed message to the stream.
async fn write_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> SocketResult<()> {
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(SocketError::MessageTooLarge(data.len(), MAX_MESSAGE_SIZE));
    }

    // Write length prefix
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Write message body
    writer.write_all(data).await?;
    writer.flush().await?;

    Ok(())
}

/// Server-side reader: reads TuiToProxy messages from socket.
async fn socket_reader(
    mut reader: tokio::net::unix::OwnedReadHalf,
    tx: mpsc::Sender<TuiToProxy>,
) -> SocketResult<()> {
    loop {
        let data = read_message(&mut reader).await?;
        let msg: TuiToProxy = bincode::deserialize(&data)?;
        debug!("Received from TUI: {:?}", msg);

        if tx.send(msg).await.is_err() {
            // Channel closed, stop reading
            break;
        }
    }
    Ok(())
}

/// Server-side writer: writes ProxyToTui messages to socket.
async fn socket_writer(
    mut writer: tokio::net::unix::OwnedWriteHalf,
    mut rx: mpsc::Receiver<ProxyToTui>,
) -> SocketResult<()> {
    while let Some(msg) = rx.recv().await {
        debug!("Sending to TUI: {:?}", msg);
        let data = bincode::serialize(&msg)?;
        write_message(&mut writer, &data).await?;
    }
    Ok(())
}

/// Client-side reader: reads ProxyToTui messages from socket.
async fn socket_reader_client(
    mut reader: tokio::net::unix::OwnedReadHalf,
    tx: mpsc::Sender<ProxyToTui>,
) -> SocketResult<()> {
    loop {
        let data = read_message(&mut reader).await?;
        let msg: ProxyToTui = bincode::deserialize(&data)?;
        debug!("Received from proxy: {:?}", msg);

        if tx.send(msg).await.is_err() {
            // Channel closed, stop reading
            break;
        }
    }
    Ok(())
}

/// Client-side writer: writes TuiToProxy messages to socket.
async fn socket_writer_client(
    mut writer: tokio::net::unix::OwnedWriteHalf,
    mut rx: mpsc::Receiver<TuiToProxy>,
) -> SocketResult<()> {
    while let Some(msg) = rx.recv().await {
        debug!("Sending to proxy: {:?}", msg);
        let data = bincode::serialize(&msg)?;
        write_message(&mut writer, &data).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_server_client_communication() {
        use crate::control::protocol::{Decision, EventCategory, LogLevel};
        use chrono::Utc;
        use uuid::Uuid;

        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Start server
        let server = ControlSocketServer::new(&socket_path).unwrap();

        // Spawn client connection
        let socket_path_clone = socket_path.clone();
        let client_handle = tokio::spawn(async move {
            // Small delay to ensure server is listening
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            ControlSocketClient::connect(&socket_path_clone).await.unwrap()
        });

        // Accept connection
        let (proxy_tx, mut tui_rx) = server.accept().await.unwrap();
        let mut client = client_handle.await.unwrap();

        // Test: proxy sends message to TUI
        let msg = ProxyToTui::PermissionRequest {
            id: Uuid::new_v4(),
            domain: "example.com".to_string(),
            port: 443,
            timestamp: Utc::now(),
        };
        proxy_tx.send(msg).await.unwrap();

        // Client receives message
        let received = client.recv().await.unwrap();
        match received {
            ProxyToTui::PermissionRequest { domain, port, .. } => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => unreachable!("Expected PermissionRequest"),
        }

        // Test: TUI sends message to proxy
        let decision = TuiToProxy::PermissionDecision {
            id: Uuid::new_v4(),
            decision: Decision::Allow,
            persist: false,
        };
        client.send(decision).await.unwrap();

        // Proxy receives message
        let received = tui_rx.recv().await.unwrap();
        match received {
            TuiToProxy::PermissionDecision { decision, persist, .. } => {
                assert_eq!(decision, Decision::Allow);
                assert!(!persist);
            }
            _ => unreachable!("Expected PermissionDecision"),
        }

        // Test: proxy sends log event
        let log_msg = ProxyToTui::LogEvent {
            level: LogLevel::Info,
            category: EventCategory::Network,
            message: "Test log".to_string(),
            timestamp: Utc::now(),
        };
        proxy_tx.send(log_msg).await.unwrap();

        let received = client.recv().await.unwrap();
        match received {
            ProxyToTui::LogEvent { message, .. } => {
                assert_eq!(message, "Test log");
            }
            _ => unreachable!("Expected LogEvent"),
        }
    }

    #[tokio::test]
    async fn test_connection_closed_detection() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test_close.sock");

        let server = ControlSocketServer::new(&socket_path).unwrap();

        let socket_path_clone = socket_path.clone();
        let client_handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            ControlSocketClient::connect(&socket_path_clone).await.unwrap()
        });

        let (proxy_tx, _tui_rx) = server.accept().await.unwrap();
        let mut client = client_handle.await.unwrap();

        // Drop proxy sender to close connection
        drop(proxy_tx);

        // Client should detect closed connection
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let result = client.recv().await;
        assert!(result.is_none());
    }
}
