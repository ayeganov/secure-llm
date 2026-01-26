//! Transport abstraction for TUI communication.

use crate::control::protocol::{ProxyToTui, TuiToProxy};
use crate::control::{ControlSocketClient, TuiChannels};

/// Transport abstraction for TUI communication.
///
/// Supports both in-process channel-based communication (for testing/debugging)
/// and Unix socket-based IPC (for production subprocess TUI).
pub enum TuiTransport {
    /// In-process channel-based communication.
    Channel(TuiChannels),
    /// Unix socket-based IPC.
    Socket(ControlSocketClient),
}

impl TuiTransport {
    /// Send a message to the proxy.
    pub async fn send(&self, msg: TuiToProxy) -> Result<(), TuiToProxy> {
        match self {
            TuiTransport::Channel(ch) => ch.send(msg).await,
            TuiTransport::Socket(sock) => sock.send(msg).await,
        }
    }

    /// Try to receive a message from the proxy without blocking.
    pub fn try_recv(&mut self) -> Option<ProxyToTui> {
        match self {
            TuiTransport::Channel(ch) => ch.try_recv(),
            TuiTransport::Socket(sock) => sock.try_recv(),
        }
    }
}
