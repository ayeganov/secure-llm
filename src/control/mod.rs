//! Control plane module for IPC communication between proxy and TUI.
//!
//! This module provides:
//! - Protocol definitions for proxy ↔ TUI messaging
//! - Bidirectional channel management
//! - Control plane coordinator that routes decisions
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐                    ┌─────────────────┐
//! │     Proxy       │                    │       TUI       │
//! │  ProxyChannels  │                    │  TuiChannels    │
//! │                 │    ProxyToTui      │                 │
//! │  .tx ───────────┼───────────────────>│ .rx             │
//! │                 │                    │                 │
//! │  .rx ◄──────────┼────────────────────│ .tx             │
//! │                 │    TuiToProxy      │                 │
//! └────────┬────────┘                    └─────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  ControlPlane   │
//! │                 │
//! │  - Routes       │
//! │    decisions    │
//! │  - Persists     │
//! │    "Always"     │
//! └─────────────────┘
//! ```

pub mod channel;
pub mod plane;
pub mod protocol;
pub mod socket;

// Re-export main types for convenient access
pub use channel::{create_channel_pair, create_channel_pair_with_size, ProxyChannels, TuiChannels};
pub use plane::ControlPlane;
pub use protocol::{
    Decision, DetectedPort, EventCategory, LogLevel, PendingPermission, ProxyToTui, TuiToProxy,
};
pub use socket::{ControlSocketClient, ControlSocketServer, SocketError, SocketResult};
