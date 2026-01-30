//! Configuration loading with hierarchy merging.
//!
//! Configuration is loaded from multiple sources and merged in order:
//!
//! 1. System config: `/etc/secure-llm/config.toml`
//! 2. User config: `~/.config/secure-llm/config.toml`
//! 3. Additional config file (via `--config` flag)
//! 4. CLI flags (highest priority)
//!
//! Lists (allowlist, blocklist) are **merged** (appended).
//! Scalars (timeout, log_level) are **overridden**.
//!
//! Note: A configuration file is required. If no config is found, the loader
//! will return a `NoConfigFound` error with helpful instructions.

use std::fs;
use std::path::PathBuf;

use tracing::debug;

use super::error::ConfigError;
use super::schema::{Config, NetworkConfig, UserAllowlist};
use crate::cli::Cli;

/// System-wide configuration path.
pub const SYSTEM_CONFIG_PATH: &str = "/etc/secure-llm/config.toml";

/// User configuration directory name.
pub const USER_CONFIG_DIR: &str = "secure-llm";

/// User configuration filename.
pub const USER_CONFIG_FILE: &str = "config.toml";

/// User allowlist filename.
pub const USER_ALLOWLIST_FILE: &str = "allowlist.toml";

/// Configuration loader with support for hierarchy merging.
pub struct ConfigLoader {
    /// Path to system-wide configuration.
    system_path: PathBuf,
    /// Path to user configuration.
    user_path: PathBuf,
    /// Path to user allowlist.
    allowlist_path: PathBuf,
}

impl ConfigLoader {
    /// Create a new ConfigLoader with default paths.
    #[must_use]
    pub fn new() -> Self {
        let user_config_dir = dirs::config_dir()
            .map(|p| p.join(USER_CONFIG_DIR))
            .unwrap_or_else(|| PathBuf::from(".config").join(USER_CONFIG_DIR));

        Self {
            system_path: PathBuf::from(SYSTEM_CONFIG_PATH),
            user_path: user_config_dir.join(USER_CONFIG_FILE),
            allowlist_path: user_config_dir.join(USER_ALLOWLIST_FILE),
        }
    }

    /// Create a ConfigLoader with custom paths (for testing).
    #[must_use]
    pub fn with_paths(system_path: PathBuf, user_path: PathBuf, allowlist_path: PathBuf) -> Self {
        Self {
            system_path,
            user_path,
            allowlist_path,
        }
    }

    /// Load and merge configuration from all sources.
    ///
    /// The merge order is:
    /// 1. System config (`/etc/secure-llm/config.toml`)
    /// 2. User config (`~/.config/secure-llm/config.toml`)
    /// 3. Additional config file (via `--config` flag)
    /// 4. CLI flags (allow-domain, etc.)
    ///
    /// At least one config file (system, user, or CLI-specified) must exist.
    /// Invalid TOML is an error (fail fast with clear message).
    pub fn load(&self, cli: &Cli) -> Result<Config, ConfigError> {
        let mut config = Config::default();
        let mut found_config = false;

        // Load and merge system config
        if let Some(system_config) = self.load_file(&self.system_path)? {
            config.merge(system_config);
            debug!("Loaded system config from {:?}", self.system_path);
            found_config = true;
        } else {
            debug!("No system config found at {:?}", self.system_path);
        }

        // Load and merge user config
        if let Some(user_config) = self.load_file(&self.user_path)? {
            config.merge(user_config);
            debug!("Loaded user config from {:?}", self.user_path);
            found_config = true;
        } else {
            debug!("No user config found at {:?}", self.user_path);
        }

        // Load and merge user allowlist/blocklist
        if let Ok(allowlist) = self.load_user_allowlist() {
            let has_allowed = !allowlist.domains.allowed.is_empty();
            let has_blocked = !allowlist.domains.blocked.is_empty();

            if has_allowed || has_blocked {
                // Create a minimal config with only the allowlist/blocklist domains - don't use
                // Default which would add duplicate graylist entries
                let allowlist_config = Config {
                    general: config.general.clone(),
                    gateway: config.gateway.clone(),
                    sandbox: Default::default(),
                    network: NetworkConfig {
                        allowlist: allowlist.domains.allowed,
                        blocklist: allowlist.domains.blocked,
                        graylist: Vec::new(),
                        host_rewrite: Default::default(),
                    },
                    filesystem: Default::default(),
                    tools: Default::default(),
                };
                config.merge(allowlist_config);
                debug!("Loaded user allowlist/blocklist from {:?}", self.allowlist_path);
            }
        }

        // Load and merge additional config file from CLI
        if let Some(ref cli_config_path) = cli.config {
            match self.load_file(cli_config_path)? {
                Some(cli_config) => {
                    config.merge(cli_config);
                    debug!("Loaded additional config from {:?}", cli_config_path);
                    found_config = true;
                }
                None => {
                    // Unlike system/user config, a missing CLI-specified config is an error
                    return Err(ConfigError::ReadError {
                        path: cli_config_path.clone(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "Specified config file not found",
                        ),
                    });
                }
            }
        }

        // Require at least one config file
        if !found_config {
            return Err(ConfigError::NoConfigFound {
                system_path: self.system_path.clone(),
                user_path: self.user_path.clone(),
            });
        }

        // Apply CLI flags (highest priority)
        if !cli.allow_domains.is_empty() {
            let cli_allowlist_config = Config {
                network: NetworkConfig {
                    allowlist: cli.allow_domains.clone(),
                    ..Default::default()
                },
                ..Default::default()
            };
            config.merge(cli_allowlist_config);
            debug!("Added {} domains from CLI flags", cli.allow_domains.len());
        }

        Ok(config)
    }

    /// Load the user's persistent allowlist.
    pub fn load_user_allowlist(&self) -> Result<UserAllowlist, ConfigError> {
        match fs::read_to_string(&self.allowlist_path) {
            Ok(contents) => {
                toml::from_str(&contents).map_err(|e| ConfigError::ParseError {
                    path: self.allowlist_path.clone(),
                    source: e,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Missing allowlist is fine - return empty
                Ok(UserAllowlist::default())
            }
            Err(e) => Err(ConfigError::ReadError {
                path: self.allowlist_path.clone(),
                source: e,
            }),
        }
    }

    /// Save a domain to the user's persistent allowlist.
    pub fn save_to_allowlist(&self, domain: &str) -> Result<(), ConfigError> {
        // Load existing allowlist
        let mut allowlist = self.load_user_allowlist().unwrap_or_default();

        // Add domain if not already present
        if !allowlist.domains.allowed.contains(&domain.to_string()) {
            allowlist.domains.allowed.push(domain.to_string());
        }

        self.write_allowlist(&allowlist)
    }

    /// Remove a domain from the user's persistent allowlist.
    pub fn remove_from_allowlist(&self, domain: &str) -> Result<(), ConfigError> {
        let mut allowlist = self.load_user_allowlist().unwrap_or_default();
        allowlist.domains.allowed.retain(|d| d != domain);
        self.write_allowlist(&allowlist)?;
        debug!("Removed domain '{}' from allowlist", domain);
        Ok(())
    }

    /// Save a domain to the user's persistent blocklist.
    pub fn save_to_blocklist(&self, domain: &str) -> Result<(), ConfigError> {
        let mut allowlist = self.load_user_allowlist().unwrap_or_default();

        // Add domain to blocklist if not already present
        if !allowlist.domains.blocked.contains(&domain.to_string()) {
            allowlist.domains.blocked.push(domain.to_string());
        }

        // Remove from allowed list if present (block takes precedence)
        allowlist.domains.allowed.retain(|d| d != domain);

        self.write_allowlist(&allowlist)
    }

    /// Remove a domain from the user's persistent blocklist.
    pub fn remove_from_blocklist(&self, domain: &str) -> Result<(), ConfigError> {
        let mut allowlist = self.load_user_allowlist().unwrap_or_default();
        allowlist.domains.blocked.retain(|d| d != domain);
        self.write_allowlist(&allowlist)?;
        debug!("Removed domain '{}' from blocklist", domain);
        Ok(())
    }

    /// Clear all entries from the user's persistent allowlist.
    pub fn clear_allowlist(&self) -> Result<(), ConfigError> {
        let allowlist = UserAllowlist::default();
        self.write_allowlist(&allowlist)?;
        debug!("Cleared all entries from allowlist");
        Ok(())
    }

    /// Get the path to the allowlist file.
    pub fn allowlist_path(&self) -> &std::path::Path {
        &self.allowlist_path
    }

    /// Write the allowlist to disk.
    fn write_allowlist(&self, allowlist: &UserAllowlist) -> Result<(), ConfigError> {
        // Ensure parent directory exists
        if let Some(parent) = self.allowlist_path.parent() {
            fs::create_dir_all(parent).map_err(|e| ConfigError::ReadError {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        // Serialize and write
        let contents = toml::to_string_pretty(allowlist)?;
        fs::write(&self.allowlist_path, contents).map_err(|e| ConfigError::ReadError {
            path: self.allowlist_path.clone(),
            source: e,
        })?;

        debug!("Wrote allowlist to {:?}", self.allowlist_path);
        Ok(())
    }

    /// Load a config file, returning None if it doesn't exist.
    fn load_file(&self, path: &PathBuf) -> Result<Option<Config>, ConfigError> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let config: Config =
                    toml::from_str(&contents).map_err(|e| ConfigError::ParseError {
                        path: path.clone(),
                        source: e,
                    })?;
                Ok(Some(config))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ConfigError::ReadError {
                path: path.clone(),
                source: e,
            }),
        }
    }

}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_cli() -> Cli {
        Cli {
            command: None,
            tool: Some("claude".to_string()),
            tool_args: vec![],
            publish: vec![],
            allow_domains: vec![],
            config: None,
            headless: false,
            verbose: 0,
        }
    }

    /// Create a minimal valid config file for testing.
    fn write_minimal_config(dir: &std::path::Path, filename: &str) {
        let config = r#"
            [general]
            prompt_timeout = 30
            log_level = "info"

            [network]
            allowlist = ["pypi.org"]
        "#;
        fs::write(dir.join(filename), config).unwrap();
    }

    #[test]
    fn test_no_config_returns_error() {
        let dir = tempdir().unwrap();
        let loader = ConfigLoader::with_paths(
            dir.path().join("nonexistent_system.toml"),
            dir.path().join("nonexistent_user.toml"),
            dir.path().join("nonexistent_allowlist.toml"),
        );

        let cli = create_test_cli();
        let result = loader.load(&cli);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::NoConfigFound { .. }));
    }

    #[test]
    fn test_user_config_overrides_system() {
        let dir = tempdir().unwrap();

        // Create system config
        let system_config = r#"
            [general]
            prompt_timeout = 60
        "#;
        fs::write(dir.path().join("system.toml"), system_config).unwrap();

        // Create user config with different value
        let user_config = r#"
            [general]
            prompt_timeout = 90
        "#;
        fs::write(dir.path().join("user.toml"), user_config).unwrap();

        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        let cli = create_test_cli();
        let config = loader.load(&cli).unwrap();

        // User config should override system config
        assert_eq!(config.general.prompt_timeout, 90);
    }

    #[test]
    fn test_lists_are_merged() {
        let dir = tempdir().unwrap();

        // Create system config with initial allowlist
        let system_config = r#"
            [network]
            allowlist = ["pypi.org"]
        "#;
        fs::write(dir.path().join("system.toml"), system_config).unwrap();

        // Create user config with additional allowlist
        let user_config = r#"
            [network]
            allowlist = ["custom.example.com"]
        "#;
        fs::write(dir.path().join("user.toml"), user_config).unwrap();

        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        let cli = create_test_cli();
        let config = loader.load(&cli).unwrap();

        // Both system and user entries should be present
        assert!(config.network.allowlist.contains(&"pypi.org".to_string()));
        assert!(config.network.allowlist.contains(&"custom.example.com".to_string()));
    }

    #[test]
    fn test_cli_domains_are_added() {
        let dir = tempdir().unwrap();
        write_minimal_config(dir.path(), "system.toml");

        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        let mut cli = create_test_cli();
        cli.allow_domains = vec!["cli-domain.example.com".to_string()];

        let config = loader.load(&cli).unwrap();

        assert!(config.network.allowlist.contains(&"cli-domain.example.com".to_string()));
    }

    #[test]
    fn test_invalid_toml_returns_error() {
        let dir = tempdir().unwrap();

        // Create invalid TOML
        let invalid_toml = "this is not valid TOML [[[";
        fs::write(dir.path().join("invalid.toml"), invalid_toml).unwrap();

        let loader = ConfigLoader::with_paths(
            dir.path().join("invalid.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        let cli = create_test_cli();
        let result = loader.load(&cli);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::ParseError { .. }));
    }

    #[test]
    fn test_save_and_load_allowlist() {
        let dir = tempdir().unwrap();
        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        // Save a domain
        loader.save_to_allowlist("test.example.com").unwrap();

        // Load it back
        let allowlist = loader.load_user_allowlist().unwrap();
        assert!(allowlist.domains.allowed.contains(&"test.example.com".to_string()));
    }

    #[test]
    fn test_save_and_load_blocklist() {
        let dir = tempdir().unwrap();
        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        // Save a domain to blocklist
        loader.save_to_blocklist("evil.example.com").unwrap();

        // Load it back
        let allowlist = loader.load_user_allowlist().unwrap();
        assert!(allowlist.domains.blocked.contains(&"evil.example.com".to_string()));
    }

    #[test]
    fn test_blocklist_removes_from_allowlist() {
        let dir = tempdir().unwrap();
        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        // First allow a domain
        loader.save_to_allowlist("changeable.example.com").unwrap();
        let allowlist = loader.load_user_allowlist().unwrap();
        assert!(allowlist.domains.allowed.contains(&"changeable.example.com".to_string()));

        // Now block the same domain - should be removed from allowed
        loader.save_to_blocklist("changeable.example.com").unwrap();
        let allowlist = loader.load_user_allowlist().unwrap();
        assert!(allowlist.domains.blocked.contains(&"changeable.example.com".to_string()));
        assert!(!allowlist.domains.allowed.contains(&"changeable.example.com".to_string()));
    }

    #[test]
    fn test_blocklist_loaded_into_config() {
        let dir = tempdir().unwrap();
        write_minimal_config(dir.path(), "system.toml");

        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        // Save a domain to blocklist
        loader.save_to_blocklist("blocked.example.com").unwrap();

        // Load config and verify blocked domain is in network.blocklist
        let cli = create_test_cli();
        let config = loader.load(&cli).unwrap();
        assert!(config.network.blocklist.contains(&"blocked.example.com".to_string()));
    }

    #[test]
    fn test_remove_from_blocklist() {
        let dir = tempdir().unwrap();
        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        // Save a domain to blocklist
        loader.save_to_blocklist("temp.example.com").unwrap();
        let allowlist = loader.load_user_allowlist().unwrap();
        assert!(allowlist.domains.blocked.contains(&"temp.example.com".to_string()));

        // Remove it
        loader.remove_from_blocklist("temp.example.com").unwrap();
        let allowlist = loader.load_user_allowlist().unwrap();
        assert!(!allowlist.domains.blocked.contains(&"temp.example.com".to_string()));
    }

    #[test]
    fn test_tools_loaded_from_config() {
        let dir = tempdir().unwrap();

        let config = r#"
            [tools.claude]
            binary = "claude"
            display_name = "Claude Code"
            allowlist = ["*.anthropic.com"]
            bind_rw = ["$HOME"]

            [tools.cursor]
            binary = "cursor"
        "#;
        fs::write(dir.path().join("config.toml"), config).unwrap();

        let loader = ConfigLoader::with_paths(
            dir.path().join("config.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        let cli = create_test_cli();
        let config = loader.load(&cli).unwrap();

        assert!(config.tools.contains_key("claude"));
        assert!(config.tools.contains_key("cursor"));

        let claude = config.tools.get("claude").unwrap();
        assert_eq!(claude.binary, "claude");
        assert_eq!(claude.display_name, Some("Claude Code".to_string()));
        assert!(claude.allowlist.contains(&"*.anthropic.com".to_string()));
        assert!(claude.bind_rw.contains(&"$HOME".to_string()));
    }

    #[test]
    fn test_tools_merged_across_configs() {
        let dir = tempdir().unwrap();

        // System config with base tool config
        let system_config = r#"
            [tools.claude]
            binary = "claude"
            allowlist = ["*.anthropic.com"]
        "#;
        fs::write(dir.path().join("system.toml"), system_config).unwrap();

        // User config extends the tool
        let user_config = r#"
            [tools.claude]
            display_name = "Claude Code"
            allowlist = ["extra.com"]
            bind_rw = ["$HOME"]
        "#;
        fs::write(dir.path().join("user.toml"), user_config).unwrap();

        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        let cli = create_test_cli();
        let config = loader.load(&cli).unwrap();

        let claude = config.tools.get("claude").unwrap();
        // Binary should come from system
        assert_eq!(claude.binary, "claude");
        // Display name from user
        assert_eq!(claude.display_name, Some("Claude Code".to_string()));
        // Allowlists should be merged
        assert!(claude.allowlist.contains(&"*.anthropic.com".to_string()));
        assert!(claude.allowlist.contains(&"extra.com".to_string()));
        // Bind mounts from user
        assert!(claude.bind_rw.contains(&"$HOME".to_string()));
    }
}
