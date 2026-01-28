//! Port monitoring and forwarding module.
//!
//! This module provides:
//! - Detection of new listening ports inside the sandbox
//! - Pre-configured port mapping (--publish flag)
//! - Dynamic port bridging (Phase 5 will add TUI prompts)
//! - Namespace-crossing TCP forwarding
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Sandbox (Network NS)                      │
//! │                                                              │
//! │  ┌─────────────┐     Port Detection                         │
//! │  │  Tool       │     (/proc/<pid>/net/tcp)                   │
//! │  │  (listening │◄────────────────────────────┐              │
//! │  │   on :3000) │                             │              │
//! │  └──────┬──────┘                             │              │
//! │         │                                    │              │
//! │         │ veth (10.200.0.2)                  │              │
//! └─────────┼────────────────────────────────────┼──────────────┘
//!           │                                    │
//!           ▼                                    │
//! ┌─────────────────────┐               ┌───────┴───────┐
//! │    Port Forwarder   │               │ Port Detector │
//! │  (host:3000 ->      │               │ (polls every  │
//! │   10.200.0.2:3000)  │               │  2 seconds)   │
//! └─────────────────────┘               └───────────────┘
//!           │
//!           ▼
//! ┌─────────────────────┐
//! │   Host Network      │
//! │   (0.0.0.0:3000)    │
//! │                     │
//! │   curl localhost:3000  ───────────► Works!
//! └─────────────────────┘
//! ```
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use secure_llm::portmon::{PortDetector, PortForwardManager, PortEvent, PortState};
//! use std::time::Duration;
//! use std::net::Ipv4Addr;
//!
//! let sandbox_pid = std::process::id(); // In practice, this is the sandbox PID
//! let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
//!
//! // Start port detection
//! let detector = PortDetector::new(sandbox_pid, Duration::from_secs(2));
//! let (tx, mut rx) = tokio::sync::mpsc::channel::<PortEvent>(32);
//! // tokio::spawn(detector.run(tx, shutdown_rx.clone()));
//!
//! // Set up static port forwards from --publish flags
//! let mut manager = PortForwardManager::new(Ipv4Addr::new(10, 200, 0, 2));
//! manager.start_forward(3000, 3000)?;
//!
//! // List active forwards
//! println!("Active forwards: {:?}", manager.list_forwards());
//! # Ok(())
//! # }
//! ```

pub mod bridge;
pub mod detector;
pub mod error;
pub mod forwarder;

// Re-export main types for convenient access
pub use bridge::{BridgeInfo, PortBridgeManager};
pub use detector::{ListeningPort, PortDetector, PortEvent, PortState};
pub use error::{PortMonError, PortMonResult};
pub use forwarder::{ForwardConfig, PortForwardManager, PortForwarder};
