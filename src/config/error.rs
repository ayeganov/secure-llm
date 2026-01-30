//! Configuration error types.

use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during configuration loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read a configuration file.
    #[error("Failed to read config file {path}: {source}")]
    ReadError {
        /// Path to the file that couldn't be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to parse a TOML configuration file.
    #[error("Failed to parse config file {path}: {source}")]
    ParseError {
        /// Path to the file that couldn't be parsed.
        path: PathBuf,
        /// The underlying TOML parse error.
        source: toml::de::Error,
    },

    /// No configuration file was found.
    ///
    /// secure-llm requires a configuration file to operate. This error is
    /// returned when neither system nor user config files exist.
    #[error("No configuration file found. secure-llm requires a config file.\n\nLooked in:\n  - {system_path}\n  - {user_path}\n\nInstall default config: sudo cp /usr/share/secure-llm/config.toml /etc/secure-llm/")]
    NoConfigFound {
        /// Path where system config was expected.
        system_path: PathBuf,
        /// Path where user config was expected.
        user_path: PathBuf,
    },

    /// Requested an unknown tool.
    ///
    /// The tool name is not defined in the configuration.
    #[error("Unknown tool '{tool}'. This tool is not defined in your configuration.\n\nAvailable tools: {available}\n\nAdd a [tools.{tool}] section to your config file.")]
    UnknownTool {
        /// The tool name that was requested.
        tool: String,
        /// Comma-separated list of available tool names.
        available: String,
    },

    /// A configuration value is invalid.
    #[error("Invalid config value for {field}: {message}")]
    InvalidValue {
        /// The field name that has an invalid value.
        field: String,
        /// Description of why the value is invalid.
        message: String,
    },

    /// Failed to determine user's home directory.
    #[error("Could not determine home directory")]
    NoHomeDirectory,

    /// Failed to serialize configuration.
    #[error("Failed to serialize config: {0}")]
    SerializeError(#[from] toml::ser::Error),
}
