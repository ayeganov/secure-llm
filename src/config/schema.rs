//! Configuration schema definitions.
//!
//! This module defines the structure of the secure-llm configuration files.
//! Configuration is loaded from multiple sources and merged in order:
//!
//! 1. System config: `/etc/secure-llm/config.toml`
//! 2. User config: `~/.config/secure-llm/config.toml`
//! 3. Additional config file (via `--config` flag)
//! 4. CLI flags (highest priority)
//!
//! Note: A configuration file is required. If no config is found, secure-llm
//! will fail with a helpful error message.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Top-level configuration structure.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    /// General settings.
    #[serde(default)]
    pub general: GeneralConfig,

    /// LLM gateway settings.
    #[serde(default)]
    pub gateway: GatewayConfig,

    /// Sandbox settings.
    #[serde(default)]
    pub sandbox: SandboxConfig,

    /// Network policy settings.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Filesystem policy settings.
    #[serde(default)]
    pub filesystem: FilesystemConfig,

    /// Tool-specific configurations.
    ///
    /// Each key is a tool name (e.g., "claude", "cursor") and the value
    /// contains tool-specific settings like binary path, allowlist, etc.
    #[serde(default)]
    pub tools: HashMap<String, ToolConfig>,
}

impl Config {
    /// Merge another config into this one.
    ///
    /// Lists (allowlist, blocklist, etc.) are merged (appended).
    /// Scalars (timeout, log_level, etc.) are overridden.
    /// Tools are merged by key, with tool-specific merge rules.
    pub fn merge(&mut self, other: Config) {
        self.general.merge(other.general);
        self.gateway.merge(other.gateway);
        self.sandbox.merge(other.sandbox);
        self.network.merge(other.network);
        self.filesystem.merge(other.filesystem);

        // Merge tools by key
        for (name, other_tool) in other.tools {
            if let Some(existing) = self.tools.get_mut(&name) {
                existing.merge(other_tool);
            } else {
                self.tools.insert(name, other_tool);
            }
        }
    }

    /// Get the list of available tool names.
    pub fn available_tools(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }
}

/// General application settings.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GeneralConfig {
    /// Timeout for permission prompts in seconds. 0 = no timeout.
    #[serde(default)]
    pub prompt_timeout: u32,

    /// Log level: trace, debug, info, warn, error
    #[serde(default)]
    pub log_level: String,
}

impl GeneralConfig {
    fn merge(&mut self, other: GeneralConfig) {
        // Scalars are overridden if non-default
        if other.prompt_timeout != 0 {
            self.prompt_timeout = other.prompt_timeout;
        }
        if !other.log_level.is_empty() {
            self.log_level = other.log_level;
        }
    }
}

/// LLM gateway configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GatewayConfig {
    /// Corporate LLM gateway URL.
    #[serde(default)]
    pub url: String,

    /// Timeout for gateway connections in milliseconds.
    #[serde(default)]
    pub timeout_ms: u32,
}

impl GatewayConfig {
    fn merge(&mut self, other: GatewayConfig) {
        // Scalars are overridden if non-default
        if !other.url.is_empty() {
            self.url = other.url;
        }
        if other.timeout_ms != 0 {
            self.timeout_ms = other.timeout_ms;
        }
    }
}

/// Sandbox configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SandboxConfig {
    /// Additional environment variables to inject into the sandbox.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl SandboxConfig {
    fn merge(&mut self, other: SandboxConfig) {
        // Environment variables are merged (later values override)
        self.env.extend(other.env);
    }
}

/// Network policy configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct NetworkConfig {
    /// Domains to allow (permit without prompting).
    ///
    /// Supports wildcards: `*.example.com` matches `sub.example.com`.
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// Domains to block (reject without prompting).
    ///
    /// Supports wildcards: `*.malware.com` matches `api.malware.com`.
    #[serde(default)]
    pub blocklist: Vec<String>,

    /// Domains that ALWAYS prompt, even if they match allowlist wildcards.
    ///
    /// Used for user-content hosting domains (raw.githubusercontent.com, etc.)
    /// that could serve malicious payloads.
    #[serde(default)]
    pub graylist: Vec<String>,

    /// Host rewriting rules (original -> replacement).
    ///
    /// Used to redirect LLM provider domains to the corporate gateway.
    #[serde(default)]
    pub host_rewrite: HashMap<String, String>,
}

impl NetworkConfig {
    fn merge(&mut self, other: NetworkConfig) {
        // Lists are merged (appended)
        self.allowlist.extend(other.allowlist);
        self.blocklist.extend(other.blocklist);
        self.graylist.extend(other.graylist);

        // Maps are merged (later values override)
        self.host_rewrite.extend(other.host_rewrite);
    }
}

/// Tool-specific configuration.
///
/// Each tool (claude, cursor, etc.) can have its own settings that are merged
/// with the base configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ToolConfig {
    /// Binary name or path to the tool executable.
    #[serde(default)]
    pub binary: String,

    /// Human-readable display name for the tool.
    #[serde(default)]
    pub display_name: Option<String>,

    /// Additional domains to allow for this tool (merged with base allowlist).
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// Environment variables specific to this tool (merged with base env).
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Host rewriting rules specific to this tool (merged with base rewrites).
    #[serde(default)]
    pub host_rewrite: HashMap<String, String>,

    /// Directories to bind mount read-only for this tool.
    ///
    /// Supports `$HOME` and `${HOME}` expansion. Paths are same-path mounts
    /// (source and destination are the same).
    #[serde(default)]
    pub bind_ro: Vec<String>,

    /// Directories to bind mount read-write for this tool.
    ///
    /// Supports `$HOME` and `${HOME}` expansion. Paths are same-path mounts
    /// (source and destination are the same).
    #[serde(default)]
    pub bind_rw: Vec<String>,
}

impl ToolConfig {
    /// Merge another tool config into this one.
    ///
    /// - `binary`: Later wins if non-empty
    /// - `display_name`: Later wins if set
    /// - `allowlist`, `bind_ro`, `bind_rw`: Appended (merged)
    /// - `env`, `host_rewrite`: Merged (later keys override)
    pub fn merge(&mut self, other: ToolConfig) {
        if !other.binary.is_empty() {
            self.binary = other.binary;
        }
        if other.display_name.is_some() {
            self.display_name = other.display_name;
        }
        self.allowlist.extend(other.allowlist);
        self.env.extend(other.env);
        self.host_rewrite.extend(other.host_rewrite);
        self.bind_ro.extend(other.bind_ro);
        self.bind_rw.extend(other.bind_rw);
    }

    /// Get the display name, falling back to binary name if not set.
    pub fn display_name_or_binary(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.binary)
    }
}

/// Filesystem policy configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FilesystemConfig {
    /// Mount sources to deny (NFS exports, block device UUIDs, etc.).
    ///
    /// Examples:
    /// - `10.1.2.3:/secure-exports` (NFS export)
    /// - `UUID=abc123-def456-...` (block device)
    #[serde(default)]
    pub denylist: Vec<String>,

    /// Paths to allow (still subject to mount source check).
    #[serde(default)]
    pub allowed_paths: Vec<PathBuf>,

    /// Directories to bind mount read-only into the sandbox.
    ///
    /// These paths will be mounted at the same location inside the sandbox.
    /// Use for directories the tool needs to read but not modify.
    ///
    /// Example: `["/opt/tools", "/usr/local/share"]`
    #[serde(default)]
    pub bind_ro: Vec<PathBuf>,

    /// Directories to bind mount read-write into the sandbox.
    ///
    /// These paths will be mounted at the same location inside the sandbox.
    /// Use for directories the tool needs to read and write.
    ///
    /// Example: `["/home/user/.cache/pip"]`
    #[serde(default)]
    pub bind_rw: Vec<PathBuf>,
}

impl FilesystemConfig {
    fn merge(&mut self, other: FilesystemConfig) {
        // Lists are merged (appended)
        self.denylist.extend(other.denylist);
        self.allowed_paths.extend(other.allowed_paths);
        self.bind_ro.extend(other.bind_ro);
        self.bind_rw.extend(other.bind_rw);
    }
}

/// User's persistent allowlist (stored separately from main config).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct UserAllowlist {
    /// Persistently allowed domains (from "Always Allow" decisions).
    #[serde(default)]
    pub domains: AllowedDomains,
}

/// Domains section of the user allowlist.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AllowedDomains {
    /// List of allowed domain names.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// List of blocked domain names.
    #[serde(default)]
    pub blocked: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_empty() {
        let config = Config::default();

        // All defaults are empty now - config file is required
        assert_eq!(config.general.prompt_timeout, 0);
        assert_eq!(config.general.log_level, "");
        assert_eq!(config.gateway.timeout_ms, 0);
        assert!(config.network.allowlist.is_empty());
        assert!(config.network.graylist.is_empty());
        assert!(config.tools.is_empty());
    }

    #[test]
    fn test_config_merge_scalars() {
        let mut base = Config::default();
        let override_config = Config {
            general: GeneralConfig {
                prompt_timeout: 60,
                log_level: "debug".to_string(),
            },
            ..Default::default()
        };

        base.merge(override_config);

        assert_eq!(base.general.prompt_timeout, 60);
        assert_eq!(base.general.log_level, "debug");
    }

    #[test]
    fn test_config_merge_lists() {
        let mut base = Config {
            network: NetworkConfig {
                allowlist: vec!["pypi.org".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let base_allowlist_len = base.network.allowlist.len();

        let override_config = Config {
            network: NetworkConfig {
                allowlist: vec!["custom.example.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        base.merge(override_config);

        // Lists should be merged, not replaced
        assert!(base.network.allowlist.len() > base_allowlist_len);
        assert!(base.network.allowlist.contains(&"custom.example.com".to_string()));
        assert!(base.network.allowlist.contains(&"pypi.org".to_string()));
    }

    #[test]
    fn test_config_deserialize() {
        let toml_str = r#"
            [general]
            prompt_timeout = 45
            log_level = "trace"

            [network]
            allowlist = ["custom.com"]
            blocklist = ["evil.com"]
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(config.general.prompt_timeout, 45);
        assert_eq!(config.general.log_level, "trace");
        assert!(config.network.allowlist.contains(&"custom.com".to_string()));
        assert!(config.network.blocklist.contains(&"evil.com".to_string()));
    }

    #[test]
    fn test_config_serialize() {
        let config = Config {
            general: GeneralConfig {
                prompt_timeout: 30,
                log_level: "info".to_string(),
            },
            ..Default::default()
        };
        let toml_str = toml::to_string(&config).unwrap();

        assert!(toml_str.contains("prompt_timeout"));
    }

    #[test]
    fn test_tool_config_merge() {
        let mut base = ToolConfig {
            binary: "claude".to_string(),
            display_name: Some("Claude Code".to_string()),
            allowlist: vec!["*.anthropic.com".to_string()],
            env: HashMap::from([("KEY1".to_string(), "val1".to_string())]),
            host_rewrite: HashMap::new(),
            bind_ro: vec![],
            bind_rw: vec!["$HOME".to_string()],
        };

        let override_config = ToolConfig {
            binary: String::new(), // Empty, should not override
            display_name: None,    // None, should not override
            allowlist: vec!["extra.com".to_string()],
            env: HashMap::from([("KEY2".to_string(), "val2".to_string())]),
            host_rewrite: HashMap::from([("api.anthropic.com".to_string(), "gateway.corp".to_string())]),
            bind_ro: vec!["/opt/tools".to_string()],
            bind_rw: vec![],
        };

        base.merge(override_config);

        // Binary should not change (override was empty)
        assert_eq!(base.binary, "claude");
        // Display name should not change (override was None)
        assert_eq!(base.display_name, Some("Claude Code".to_string()));
        // Lists should be merged
        assert_eq!(base.allowlist.len(), 2);
        assert!(base.allowlist.contains(&"extra.com".to_string()));
        // Maps should be merged
        assert_eq!(base.env.len(), 2);
        assert_eq!(base.env.get("KEY2"), Some(&"val2".to_string()));
        assert_eq!(base.host_rewrite.len(), 1);
        // Bind mounts should be merged
        assert_eq!(base.bind_ro.len(), 1);
        assert_eq!(base.bind_rw.len(), 1);
    }

    #[test]
    fn test_config_tools_merge() {
        let mut base = Config {
            tools: HashMap::from([
                ("claude".to_string(), ToolConfig {
                    binary: "claude".to_string(),
                    allowlist: vec!["*.anthropic.com".to_string()],
                    ..Default::default()
                }),
            ]),
            ..Default::default()
        };

        let override_config = Config {
            tools: HashMap::from([
                ("claude".to_string(), ToolConfig {
                    allowlist: vec!["extra.com".to_string()],
                    ..Default::default()
                }),
                ("cursor".to_string(), ToolConfig {
                    binary: "cursor".to_string(),
                    ..Default::default()
                }),
            ]),
            ..Default::default()
        };

        base.merge(override_config);

        // Claude tool should be merged
        let claude = base.tools.get("claude").unwrap();
        assert_eq!(claude.binary, "claude");
        assert_eq!(claude.allowlist.len(), 2);

        // Cursor tool should be added
        assert!(base.tools.contains_key("cursor"));
    }

    #[test]
    fn test_tool_config_deserialize() {
        let toml_str = r#"
            [tools.claude]
            binary = "claude"
            display_name = "Claude Code"
            allowlist = ["*.anthropic.com"]
            bind_rw = ["$HOME"]

            [tools.claude.env]
            ANTHROPIC_API_KEY = "secret"

            [tools.claude.host_rewrite]
            "api.anthropic.com" = "gateway.corp"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let claude = config.tools.get("claude").unwrap();

        assert_eq!(claude.binary, "claude");
        assert_eq!(claude.display_name, Some("Claude Code".to_string()));
        assert!(claude.allowlist.contains(&"*.anthropic.com".to_string()));
        assert!(claude.bind_rw.contains(&"$HOME".to_string()));
        assert_eq!(claude.env.get("ANTHROPIC_API_KEY"), Some(&"secret".to_string()));
        assert_eq!(claude.host_rewrite.get("api.anthropic.com"), Some(&"gateway.corp".to_string()));
    }

    #[test]
    fn test_available_tools() {
        let config = Config {
            tools: HashMap::from([
                ("claude".to_string(), ToolConfig::default()),
                ("cursor".to_string(), ToolConfig::default()),
            ]),
            ..Default::default()
        };

        let tools = config.available_tools();
        assert_eq!(tools.len(), 2);
        assert!(tools.contains(&"claude"));
        assert!(tools.contains(&"cursor"));
    }

    #[test]
    fn test_default_toml_parses() {
        // Verify that our shipped default config parses correctly
        let toml_content = include_str!("../../config/default.toml");
        let config: Config = toml::from_str(toml_content).expect("default.toml should parse as Config");

        // Verify expected values from the default config
        assert_eq!(config.general.prompt_timeout, 30);
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.gateway.timeout_ms, 150);

        // Verify tools are defined
        assert!(config.tools.contains_key("claude"));
        assert!(config.tools.contains_key("cursor"));
        assert!(config.tools.contains_key("gemini"));
        assert!(config.tools.contains_key("windsurf"));

        // Verify claude tool config
        let claude = config.tools.get("claude").unwrap();
        assert_eq!(claude.binary, "claude");
        assert_eq!(claude.display_name, Some("Claude Code".to_string()));
        assert!(claude.allowlist.contains(&"*.anthropic.com".to_string()));
        assert!(claude.bind_rw.contains(&"$HOME".to_string()));

        // Verify cursor tool config with nested host_rewrite
        let cursor = config.tools.get("cursor").unwrap();
        assert_eq!(cursor.binary, "cursor");
        assert!(cursor.host_rewrite.contains_key("api.cursor.sh"));

        // Verify network config from default
        assert!(!config.network.allowlist.is_empty());
        assert!(config.network.allowlist.contains(&"pypi.org".to_string()));
        assert!(config.network.graylist.contains(&"raw.githubusercontent.com".to_string()));
    }
}
