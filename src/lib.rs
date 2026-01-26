//! secure-llm: Security sandbox wrapper for agentic IDEs
//!
//! This crate provides the core functionality for sandboxing AI coding assistants
//! (Claude Code, Cursor, Windsurf) to protect corporate environments from agentic
//! security risks.
//!
//! # Security Model
//!
//! The security model is **fail-closed**: when in doubt, deny and log. This protects
//! against prompt injection, data exfiltration, and unauthorized resource access.
//!
//! # Architecture
//!
//! - **Sandbox**: Bubblewrap-based isolation with network and mount namespaces
//! - **Proxy**: Embedded MITM proxy for network policy enforcement
//! - **Config**: Hierarchical TOML configuration with embedded tool profiles
//! - **Telemetry**: Structured syslog logging for audit trails
//! - **Control**: Unix socket IPC for permission prompts
//! - **TUI**: Terminal UI for interactive permission decisions

#![warn(clippy::all)]
#![warn(missing_docs)]

pub mod cli;
pub mod cli_handler;
pub mod orchestrator;
pub mod config;
pub mod control;
pub mod portmon;
pub mod proxy;
pub mod sandbox;
pub mod shim;
pub mod telemetry;
pub mod tui;
