//! Configuration system for secure-llm.
//!
//! This module provides TOML configuration loading with hierarchy merging.
//! Tool configurations are defined in `[tools.<name>]` sections of the config file.
//!
//! # Configuration Hierarchy
//!
//! Configuration is loaded from multiple sources and merged in order:
//!
//! 1. System config: `/etc/secure-llm/config.toml`
//! 2. User config: `~/.config/secure-llm/config.toml`
//! 3. Additional config file (via `--config` flag)
//! 4. CLI flags (highest priority)
//!
//! At least one configuration file must exist. If no config is found, secure-llm
//! will fail with a helpful error message.
//!
//! # Merge Behavior
//!
//! - **Lists** (allowlist, blocklist, etc.) are **merged** (appended)
//! - **Scalars** (timeout, log_level, etc.) are **overridden**
//! - **Maps** (host_rewrite, env) are **merged** (later values override)
//! - **Tools** are merged by key, with tool-specific merge rules
//!
//! # Tool Configuration
//!
//! Tools are configured in `[tools.<name>]` sections:
//!
//! ```toml
//! [tools.claude]
//! binary = "claude"
//! display_name = "Claude Code"
//! allowlist = ["*.anthropic.com"]
//! bind_rw = ["$HOME"]
//! ```

mod error;
mod loader;
mod schema;

pub use error::ConfigError;
pub use loader::ConfigLoader;
pub use schema::{
    AllowedDomains, Config, FilesystemConfig, GatewayConfig, GeneralConfig, NetworkConfig,
    SandboxConfig, ToolConfig, UserAllowlist,
};
