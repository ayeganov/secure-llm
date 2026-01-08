//! Configuration system for secure-llm.
//!
//! This module provides TOML configuration loading with hierarchy merging
//! and embedded default tool profiles.
//!
//! # Configuration Hierarchy
//!
//! Configuration is loaded from multiple sources and merged in order:
//!
//! 1. Embedded defaults (compiled into binary)
//! 2. System config: `/etc/secure-llm/config.toml`
//! 3. User config: `~/.config/secure-llm/config.toml`
//! 4. Additional config file (via `--config` flag)
//! 5. CLI flags (highest priority)
//!
//! # Merge Behavior
//!
//! - **Lists** (allowlist, blocklist, etc.) are **merged** (appended)
//! - **Scalars** (timeout, log_level, etc.) are **overridden**
//! - **Maps** (host_rewrite, env) are **merged** (later values override)
//!
//! # Tool Profiles
//!
//! Built-in profiles for common tools (Claude Code, Cursor, Windsurf) are
//! embedded at compile time. Custom profiles can be placed in:
//!
//! - System: `/etc/secure-llm/profiles/<name>.toml`
//! - User: `~/.config/secure-llm/profiles/<name>.toml`

mod error;
mod loader;
mod profiles;
mod schema;

pub use error::ConfigError;
pub use loader::ConfigLoader;
pub use profiles::{ProfileNetworkConfig, ProfileProxyConfig, ToolInfo, ToolProfile};
pub use schema::{
    AllowedDomains, Config, FilesystemConfig, GatewayConfig, GeneralConfig, NetworkConfig,
    SandboxConfig, UserAllowlist,
};
