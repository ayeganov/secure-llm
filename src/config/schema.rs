//! Configuration schema definitions.
//!
//! This module defines the structure of the secure-llm configuration files.
//! Configuration is loaded from multiple sources and merged in order:
//!
//! 1. Embedded defaults (compiled into binary)
//! 2. System config: `/etc/secure-llm/config.toml`
//! 3. User config: `~/.config/secure-llm/config.toml`
//! 4. CLI flags (highest priority)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Default timeout for permission prompts (seconds).
const fn default_prompt_timeout() -> u32 {
    30
}

/// Default log level.
fn default_log_level() -> String {
    "info".to_string()
}

/// Default gateway timeout (milliseconds).
const fn default_gateway_timeout() -> u32 {
    150
}

/// Default gateway URL.
fn default_gateway_url() -> String {
    "https://llm-gateway.corp".to_string()
}

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
}

impl Config {
    /// Merge another config into this one.
    ///
    /// Lists (allowlist, blocklist, etc.) are merged (appended).
    /// Scalars (timeout, log_level, etc.) are overridden.
    pub fn merge(&mut self, other: Config) {
        self.general.merge(other.general);
        self.gateway.merge(other.gateway);
        self.sandbox.merge(other.sandbox);
        self.network.merge(other.network);
        self.filesystem.merge(other.filesystem);
    }
}

/// General application settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeneralConfig {
    /// Timeout for permission prompts in seconds. 0 = no timeout.
    #[serde(default = "default_prompt_timeout")]
    pub prompt_timeout: u32,

    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            prompt_timeout: default_prompt_timeout(),
            log_level: default_log_level(),
        }
    }
}

impl GeneralConfig {
    fn merge(&mut self, other: GeneralConfig) {
        // Scalars are overridden
        if other.prompt_timeout != default_prompt_timeout() {
            self.prompt_timeout = other.prompt_timeout;
        }
        if other.log_level != default_log_level() {
            self.log_level = other.log_level;
        }
    }
}

/// LLM gateway configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayConfig {
    /// Corporate LLM gateway URL.
    #[serde(default = "default_gateway_url")]
    pub url: String,

    /// Timeout for gateway connections in milliseconds.
    #[serde(default = "default_gateway_timeout")]
    pub timeout_ms: u32,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            url: default_gateway_url(),
            timeout_ms: default_gateway_timeout(),
        }
    }
}

impl GatewayConfig {
    fn merge(&mut self, other: GatewayConfig) {
        // Scalars are overridden
        if other.url != default_gateway_url() {
            self.url = other.url;
        }
        if other.timeout_ms != default_gateway_timeout() {
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            allowlist: default_allowlist(),
            blocklist: Vec::new(),
            graylist: default_graylist(),
            host_rewrite: default_host_rewrites(),
        }
    }
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

/// Default network allowlist for common package registries and VCS.
fn default_allowlist() -> Vec<String> {
    vec![
        // Python
        "pypi.org".to_string(),
        "*.pypi.org".to_string(),
        "files.pythonhosted.org".to_string(),
        // Node.js
        "registry.npmjs.org".to_string(),
        "*.npmjs.org".to_string(),
        // Git hosting
        "github.com".to_string(),
        "api.github.com".to_string(),
        "gitlab.com".to_string(),
        "*.gitlab.com".to_string(),
        "bitbucket.org".to_string(),
        "*.bitbucket.org".to_string(),
        // Linux packages
        "apt.llvm.org".to_string(),
        "*.ubuntu.com".to_string(),
        "*.debian.org".to_string(),
        // Rust
        "crates.io".to_string(),
        "*.crates.io".to_string(),
        "static.rust-lang.org".to_string(),
    ]
}

/// Default graylist for user-content domains that require prompting.
fn default_graylist() -> Vec<String> {
    vec![
        // GitHub raw content
        "raw.githubusercontent.com".to_string(),
        "*.rawgithubusercontent.com".to_string(),
        "gist.githubusercontent.com".to_string(),
        "objects.githubusercontent.com".to_string(),
        // GitLab raw content
        "raw.gitlab.com".to_string(),
        // Paste sites
        "pastebin.com".to_string(),
        "paste.debian.net".to_string(),
    ]
}

/// Default host rewrite rules for LLM providers.
fn default_host_rewrites() -> HashMap<String, String> {
    let mut rewrites = HashMap::new();
    rewrites.insert(
        "api.anthropic.com".to_string(),
        "llm-gateway.corp/v1/anthropic".to_string(),
    );
    rewrites.insert(
        "api.openai.com".to_string(),
        "llm-gateway.corp/v1/openai".to_string(),
    );
    rewrites.insert(
        "generativelanguage.googleapis.com".to_string(),
        "llm-gateway.corp/v1/google".to_string(),
    );
    rewrites
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
}

impl FilesystemConfig {
    fn merge(&mut self, other: FilesystemConfig) {
        // Lists are merged (appended)
        self.denylist.extend(other.denylist);
        self.allowed_paths.extend(other.allowed_paths);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();

        assert_eq!(config.general.prompt_timeout, 30);
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.gateway.timeout_ms, 150);
        assert!(!config.network.allowlist.is_empty());
        assert!(config.network.allowlist.contains(&"pypi.org".to_string()));
        assert!(!config.network.graylist.is_empty());
        assert!(config.network.graylist.contains(&"raw.githubusercontent.com".to_string()));
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
        let mut base = Config::default();
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
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();

        assert!(toml_str.contains("prompt_timeout"));
        assert!(toml_str.contains("pypi.org"));
    }
}
