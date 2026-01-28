//! Configuration loading with hierarchy merging.
//!
//! Configuration is loaded from multiple sources and merged in order:
//!
//! 1. Embedded defaults (compiled into binary)
//! 2. System config: `/etc/secure-llm/config.toml`
//! 3. User config: `~/.config/secure-llm/config.toml`
//! 4. Additional config file (via `--config` flag)
//! 5. CLI flags (highest priority)
//!
//! Lists (allowlist, blocklist) are **merged** (appended).
//! Scalars (timeout, log_level) are **overridden**.

use std::fs;
use std::path::PathBuf;

use tracing::{debug, warn};

use super::error::ConfigError;
use super::profiles::ToolProfile;
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
    /// 1. Embedded defaults
    /// 2. System config (`/etc/secure-llm/config.toml`)
    /// 3. User config (`~/.config/secure-llm/config.toml`)
    /// 4. Additional config file (via `--config` flag)
    /// 5. CLI flags (allow-domain, etc.)
    ///
    /// Missing config files are not errors - they are simply skipped.
    /// Invalid TOML is an error (fail fast with clear message).
    pub fn load(&self, cli: &Cli) -> Result<Config, ConfigError> {
        // Start with embedded defaults
        let mut config = Config::default();
        debug!("Loaded embedded default configuration");

        // Load and merge system config
        if let Some(system_config) = self.load_file(&self.system_path)? {
            config.merge(system_config);
            debug!("Loaded system config from {:?}", self.system_path);
        } else {
            debug!("No system config found at {:?}", self.system_path);
        }

        // Load and merge user config
        if let Some(user_config) = self.load_file(&self.user_path)? {
            config.merge(user_config);
            debug!("Loaded user config from {:?}", self.user_path);
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

    /// Load a tool profile by name.
    ///
    /// Resolution order:
    /// 1. If `profile_override` is provided, use that profile name
    /// 2. Try to find an embedded profile matching the tool name
    /// 3. Try to load from user config directory (`~/.config/secure-llm/profiles/<name>.toml`)
    /// 4. Try to load from system directory (`/etc/secure-llm/profiles/<name>.toml`)
    /// 5. If the tool name looks like a path, use the tool name as-is and create a minimal profile
    pub fn load_profile(
        &self,
        tool: &str,
        profile_override: Option<&str>,
    ) -> Result<ToolProfile, ConfigError> {
        let profile_name = profile_override.unwrap_or(tool);

        // Try embedded profile first
        if let Some(embedded) = ToolProfile::get_embedded(profile_name) {
            let profile: ToolProfile =
                toml::from_str(embedded).map_err(|e| ConfigError::ParseError {
                    path: PathBuf::from(format!("<embedded:{}>", profile_name)),
                    source: e,
                })?;
            debug!("Using embedded profile for '{}'", profile_name);
            return Ok(profile);
        }

        // Try user profiles directory
        let user_profile_path = self
            .user_path
            .parent()
            .map(|p| p.join("profiles").join(format!("{}.toml", profile_name)));

        if let Some(ref path) = user_profile_path
            && let Some(profile) = self.load_profile_file(path)?
        {
            debug!("Loaded user profile from {:?}", path);
            return Ok(profile);
        }

        // Try system profiles directory
        let system_profile_path = PathBuf::from("/etc/secure-llm/profiles")
            .join(format!("{}.toml", profile_name));

        if let Some(profile) = self.load_profile_file(&system_profile_path)? {
            debug!("Loaded system profile from {:?}", system_profile_path);
            return Ok(profile);
        }

        // If the tool looks like a path (contains / or exists), create a minimal profile
        if tool.contains('/') || PathBuf::from(tool).exists() {
            debug!("Creating minimal profile for path-based tool: {}", tool);
            return Ok(ToolProfile {
                tool: super::profiles::ToolInfo {
                    name: tool.to_string(),
                    display_name: tool.to_string(),
                    binary: tool.to_string(),
                    description: format!("Custom tool: {}", tool),
                },
                environment: Default::default(),
                network: Default::default(),
                proxy: Default::default(),
            });
        }

        // No profile found
        warn!(
            "No profile found for '{}'. Available built-in profiles: {:?}",
            profile_name,
            ToolProfile::builtin_names()
        );
        Err(ConfigError::UnknownProfile(profile_name.to_string()))
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

    /// Load a profile file, returning None if it doesn't exist.
    fn load_profile_file(&self, path: &PathBuf) -> Result<Option<ToolProfile>, ConfigError> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let profile: ToolProfile =
                    toml::from_str(&contents).map_err(|e| ConfigError::ParseError {
                        path: path.clone(),
                        source: e,
                    })?;
                Ok(Some(profile))
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
            profile: None,
            headless: false,
            verbose: 0,
        }
    }

    #[test]
    fn test_default_config_is_valid() {
        let loader = ConfigLoader::new();
        let cli = create_test_cli();
        let config = loader.load(&cli).unwrap();

        assert!(!config.network.allowlist.is_empty());
        assert_eq!(config.general.prompt_timeout, 30);
    }

    #[test]
    fn test_missing_files_use_defaults() {
        let dir = tempdir().unwrap();
        let loader = ConfigLoader::with_paths(
            dir.path().join("nonexistent_system.toml"),
            dir.path().join("nonexistent_user.toml"),
            dir.path().join("nonexistent_allowlist.toml"),
        );

        let cli = create_test_cli();
        let config = loader.load(&cli).unwrap();

        // Should still have defaults
        assert!(!config.network.allowlist.is_empty());
        assert!(config.network.allowlist.contains(&"pypi.org".to_string()));
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

        // Create user config with additional allowlist
        let user_config = r#"
            [network]
            allowlist = ["custom.example.com"]
        "#;
        fs::write(dir.path().join("user.toml"), user_config).unwrap();

        let loader = ConfigLoader::with_paths(
            dir.path().join("nonexistent.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        let cli = create_test_cli();
        let config = loader.load(&cli).unwrap();

        // Both default allowlist entries and user entries should be present
        assert!(config.network.allowlist.contains(&"pypi.org".to_string()));
        assert!(config.network.allowlist.contains(&"custom.example.com".to_string()));
    }

    #[test]
    fn test_cli_domains_are_added() {
        let dir = tempdir().unwrap();
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
    fn test_embedded_profiles_parse() {
        let loader = ConfigLoader::new();

        for name in ToolProfile::builtin_names() {
            let profile = loader.load_profile(name, None).unwrap();
            assert_eq!(profile.tool.name, *name);
        }
    }

    #[test]
    fn test_unknown_profile_returns_error() {
        let dir = tempdir().unwrap();
        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        let result = loader.load_profile("unknown-tool", None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::UnknownProfile(_)));
    }

    #[test]
    fn test_path_based_tool_creates_minimal_profile() {
        let dir = tempdir().unwrap();
        let loader = ConfigLoader::with_paths(
            dir.path().join("system.toml"),
            dir.path().join("user.toml"),
            dir.path().join("allowlist.toml"),
        );

        // Tool name that looks like a path
        let profile = loader.load_profile("/usr/local/bin/custom-tool", None).unwrap();

        assert_eq!(profile.tool.binary, "/usr/local/bin/custom-tool");
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
    fn test_profile_override() {
        let loader = ConfigLoader::new();

        // Request claude but override with cursor profile
        let profile = loader.load_profile("claude", Some("cursor")).unwrap();

        // Should get cursor profile, not claude
        assert_eq!(profile.tool.name, "cursor");
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
}
