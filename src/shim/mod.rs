//! Shim module for rootless socket proxying.
//!
//! This module provides lightweight forwarders that run inside the sandbox
//! to bridge TCP traffic to Unix sockets on the host.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Sandbox (rootless)                       │
//! │                                                             │
//! │   ┌──────────────┐         ┌───────────────────────────┐   │
//! │   │  Tool        │ HTTP    │     EgressShim            │   │
//! │   │  (claude,    │ PROXY   │  TCP 127.0.0.1:8080       │   │
//! │   │   cursor)    │────────►│         │                 │   │
//! │   └──────────────┘         │         ▼                 │   │
//! │                            │  /tmp/proxy.sock ─────────┼───┼──┐
//! │                            └───────────────────────────┘   │  │
//! └─────────────────────────────────────────────────────────────┘  │
//!                                                                  │
//! ┌────────────────────────────────────────────────────────────────┼──┐
//! │                     Host                                       │  │
//! │                                                                │  │
//! │   ┌───────────────────────────────────────────────────────┐    │  │
//! │   │               ProxyServer                             │◄───┘  │
//! │   │           Unix Socket Listener                        │       │
//! │   │        /tmp/secure-llm/proxy.sock                     │       │
//! │   │                    │                                  │       │
//! │   │                    ▼                                  │       │
//! │   │              (to internet)                            │       │
//! │   └───────────────────────────────────────────────────────┘       │
//! └────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Points
//!
//! - **No root required**: Uses `--unshare-net` for empty network stack
//! - **Unix socket bridge**: Proxy socket is bind-mounted into sandbox
//! - **Internal shim**: Runs as background process inside sandbox
//! - **Transparent to tools**: Tools just see HTTP_PROXY=127.0.0.1:8080

pub mod egress;

// Re-export main entry point
pub use egress::run;
