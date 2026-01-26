//! Control plane channel management.
//!
//! This module provides channel wrappers for bidirectional IPC communication
//! between the proxy and TUI.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────┐                    ┌────────────────┐
//! │     Proxy      │                    │      TUI       │
//! │                │                    │                │
//! │  proxy_tx ─────┼──► proxy_rx ───────┼► (receives)    │
//! │                │                    │                │
//! │  (receives) ◄──┼─── tui_tx ◄────────┼── tui_tx       │
//! └────────────────┘                    └────────────────┘
//! ```

use super::protocol::{ProxyToTui, TuiToProxy};
use tokio::sync::mpsc;

/// Default channel buffer size.
pub const DEFAULT_CHANNEL_SIZE: usize = 64;

/// Channels for proxy-side communication.
///
/// The proxy holds this to send messages to TUI and receive decisions back.
#[derive(Debug)]
pub struct ProxyChannels {
    /// Sender for messages to TUI (permission requests, port detections, logs).
    pub tx: mpsc::Sender<ProxyToTui>,
    /// Receiver for messages from TUI (decisions).
    pub rx: mpsc::Receiver<TuiToProxy>,
}

/// Channels for TUI-side communication.
///
/// The TUI holds this to receive messages from proxy and send decisions back.
#[derive(Debug)]
pub struct TuiChannels {
    /// Receiver for messages from proxy.
    pub rx: mpsc::Receiver<ProxyToTui>,
    /// Sender for messages to proxy.
    pub tx: mpsc::Sender<TuiToProxy>,
}

/// Create a pair of connected channel sets for proxy and TUI.
///
/// Returns `(ProxyChannels, TuiChannels)`.
///
/// # Example
///
/// ```
/// use secure_llm::control::channel::create_channel_pair;
///
/// let (proxy_channels, tui_channels) = create_channel_pair();
///
/// // Proxy sends to TUI
/// // proxy_channels.tx.send(ProxyToTui::...).await;
///
/// // TUI receives from proxy
/// // tui_channels.rx.recv().await;
/// ```
#[inline]
pub fn create_channel_pair() -> (ProxyChannels, TuiChannels) {
    create_channel_pair_with_size(DEFAULT_CHANNEL_SIZE)
}

/// Create a pair of connected channel sets with custom buffer sizes.
pub fn create_channel_pair_with_size(size: usize) -> (ProxyChannels, TuiChannels) {
    // Proxy -> TUI channel
    let (proxy_tx, tui_rx) = mpsc::channel(size);
    // TUI -> Proxy channel
    let (tui_tx, proxy_rx) = mpsc::channel(size);

    let proxy_channels = ProxyChannels {
        tx: proxy_tx,
        rx: proxy_rx,
    };

    let tui_channels = TuiChannels {
        rx: tui_rx,
        tx: tui_tx,
    };

    (proxy_channels, tui_channels)
}

impl ProxyChannels {
    /// Send a message to the TUI.
    ///
    /// Returns `Ok(())` if the message was sent, or `Err(msg)` if the TUI
    /// receiver has been dropped.
    pub async fn send(&self, msg: ProxyToTui) -> Result<(), ProxyToTui> {
        self.tx.send(msg).await.map_err(|e| e.0)
    }

    /// Try to receive a message from the TUI without blocking.
    ///
    /// Returns `None` if no message is available or the channel is closed.
    pub fn try_recv(&mut self) -> Option<TuiToProxy> {
        self.rx.try_recv().ok()
    }

    /// Receive a message from the TUI, blocking until one is available.
    ///
    /// Returns `None` if the TUI sender has been dropped.
    pub async fn recv(&mut self) -> Option<TuiToProxy> {
        self.rx.recv().await
    }
}

impl TuiChannels {
    /// Send a message to the proxy.
    ///
    /// Returns `Ok(())` if the message was sent, or `Err(msg)` if the proxy
    /// receiver has been dropped.
    pub async fn send(&self, msg: TuiToProxy) -> Result<(), TuiToProxy> {
        self.tx.send(msg).await.map_err(|e| e.0)
    }

    /// Try to receive a message from the proxy without blocking.
    ///
    /// Returns `None` if no message is available or the channel is closed.
    pub fn try_recv(&mut self) -> Option<ProxyToTui> {
        self.rx.try_recv().ok()
    }

    /// Receive a message from the proxy, blocking until one is available.
    ///
    /// Returns `None` if the proxy sender has been dropped.
    pub async fn recv(&mut self) -> Option<ProxyToTui> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_proxy_to_tui_message() {
        let (proxy, mut tui) = create_channel_pair();

        let msg = ProxyToTui::PermissionRequest {
            id: Uuid::new_v4(),
            domain: "example.com".to_string(),
            port: 443,
            timestamp: Utc::now(),
        };

        proxy.send(msg.clone()).await.unwrap();

        let received = tui.recv().await.unwrap();
        match received {
            ProxyToTui::PermissionRequest { domain, .. } => {
                assert_eq!(domain, "example.com");
            }
            _ => unreachable!("Expected PermissionRequest"),
        }
    }

    #[tokio::test]
    async fn test_tui_to_proxy_message() {
        let (mut proxy, tui) = create_channel_pair();

        let id = Uuid::new_v4();
        let msg = TuiToProxy::PermissionDecision {
            id,
            decision: super::super::protocol::Decision::Allow,
            persist: false,
        };

        tui.send(msg).await.unwrap();

        let received = proxy.recv().await.unwrap();
        match received {
            TuiToProxy::PermissionDecision { id: recv_id, decision, .. } => {
                assert_eq!(recv_id, id);
                assert_eq!(decision, super::super::protocol::Decision::Allow);
            }
            _ => unreachable!("Expected PermissionDecision"),
        }
    }

    #[tokio::test]
    async fn test_try_recv_empty() {
        let (mut proxy, mut tui) = create_channel_pair();

        // Nothing sent yet
        assert!(proxy.try_recv().is_none());
        assert!(tui.try_recv().is_none());
    }

    #[tokio::test]
    async fn test_channel_drop_detection() {
        let (proxy, tui) = create_channel_pair();

        // Drop the TUI receiver
        drop(tui);

        // Sending should fail
        let msg = ProxyToTui::Shutdown;
        let result = proxy.send(msg).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_channel_size() {
        let (proxy, _tui) = create_channel_pair_with_size(128);

        // Channels should be created successfully
        assert!(proxy.tx.capacity() >= 128);
    }
}
