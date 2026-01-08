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

    /// Requested an unknown tool profile.
    #[error("Unknown tool profile: {0}")]
    UnknownProfile(String),

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
