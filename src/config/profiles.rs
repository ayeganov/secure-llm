//! Tool profile definitions and embedded defaults.
//!
//! Tool profiles configure secure-llm for specific agentic IDEs (Claude Code,
//! Cursor, Windsurf). Profiles are embedded at compile time for built-in tools
//! and can also be loaded from the filesystem for custom tools.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Embedded profile for Claude Code.
pub const PROFILE_CLAUDE: &str = include_str!("../../profiles/claude.toml");

/// Embedded profile for Cursor IDE.
pub const PROFILE_CURSOR: &str = include_str!("../../profiles/cursor.toml");

/// Embedded profile for Windsurf IDE.
pub const PROFILE_WINDSURF: &str = include_str!("../../profiles/windsurf.toml");

/// Embedded profile for Google Gemini CLI.
pub const PROFILE_GEMINI: &str = include_str!("../../profiles/gemini.toml");

/// Complete tool profile configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolProfile {
    /// Basic tool information.
    pub tool: ToolInfo,

    /// Environment variables to inject into the sandbox.
    ///
    /// Supports `${SANDBOX_CA_CERT}` placeholder for CA certificate path.
    /// Environment variables are NOT expanded at load time - they are
    /// expanded at sandbox launch time.
    #[serde(default)]
    pub environment: HashMap<String, String>,

    /// Tool-specific network configuration.
    #[serde(default)]
    pub network: ProfileNetworkConfig,

    /// Tool-specific proxy configuration.
    #[serde(default)]
    pub proxy: ProfileProxyConfig,
}

/// Basic information about a tool.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolInfo {
    /// Internal name (used for profile lookup).
    pub name: String,

    /// Human-readable display name.
    pub display_name: String,

    /// Binary name or path.
    pub binary: String,

    /// Optional description.
    #[serde(default)]
    pub description: String,
}

/// Tool-specific network configuration (merged with base config).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ProfileNetworkConfig {
    /// Additional domains to allow for this tool.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// Tool-specific proxy configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ProfileProxyConfig {
    /// Host rewriting rules specific to this tool.
    #[serde(default)]
    pub host_rewrite: HashMap<String, String>,
}

impl ToolProfile {
    /// Get the embedded profile for a built-in tool.
    ///
    /// Returns None if the tool name doesn't match a built-in profile.
    pub fn get_embedded(name: &str) -> Option<&'static str> {
        match name {
            "claude" => Some(PROFILE_CLAUDE),
            "cursor" => Some(PROFILE_CURSOR),
            "windsurf" => Some(PROFILE_WINDSURF),
            "gemini" => Some(PROFILE_GEMINI),
            _ => None,
        }
    }

    /// List all built-in profile names.
    pub fn builtin_names() -> &'static [&'static str] {
        &["claude", "cursor", "windsurf", "gemini"]
    }

    /// Check if a name matches a built-in profile.
    pub fn is_builtin(name: &str) -> bool {
        Self::builtin_names().contains(&name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_embedded_profile() {
        assert!(ToolProfile::get_embedded("claude").is_some());
        assert!(ToolProfile::get_embedded("cursor").is_some());
        assert!(ToolProfile::get_embedded("windsurf").is_some());
        assert!(ToolProfile::get_embedded("gemini").is_some());
        assert!(ToolProfile::get_embedded("unknown").is_none());
    }

    #[test]
    fn test_is_builtin() {
        assert!(ToolProfile::is_builtin("claude"));
        assert!(ToolProfile::is_builtin("cursor"));
        assert!(ToolProfile::is_builtin("windsurf"));
        assert!(ToolProfile::is_builtin("gemini"));
        assert!(!ToolProfile::is_builtin("custom-tool"));
    }

    #[test]
    fn test_builtin_names() {
        let names = ToolProfile::builtin_names();
        assert!(names.contains(&"claude"));
        assert!(names.contains(&"cursor"));
        assert!(names.contains(&"windsurf"));
        assert!(names.contains(&"gemini"));
    }

    // Profile parsing tests are in loader.rs since they depend on
    // the actual TOML files being created.
}
