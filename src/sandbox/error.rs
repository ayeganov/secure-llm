//! Error types for sandbox operations.
//!
//! This module defines structured error types for all sandbox components:
//! - Mount verification errors (denied paths, failed canonicalization)
//! - CA certificate errors (generation, file operations)
//! - Bubblewrap errors (command construction, execution)

use std::path::PathBuf;
use thiserror::Error;

/// Unified error type for all sandbox operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Mount verification failed.
    #[error("Mount verification failed: {0}")]
    Mount(#[from] MountError),

    /// CA certificate operation failed.
    #[error("CA certificate error: {0}")]
    Ca(#[from] CaError),

    /// Bubblewrap execution failed.
    #[error("Bubblewrap execution failed: {0}")]
    Bwrap(String),

    /// Process operation failed.
    #[error("Sandbox process error: {0}")]
    Process(#[from] std::io::Error),

    /// Configuration error.
    #[error("Sandbox configuration error: {0}")]
    Config(String),
}

/// Errors related to mount source verification.
///
/// These errors occur when verifying that paths don't resolve to
/// sensitive mount sources (NFS exports, restricted block devices).
#[derive(Debug, Error)]
pub enum MountError {
    /// Failed to read /proc/self/mountinfo.
    #[error("Failed to read mountinfo: {0}")]
    MountInfoRead(#[source] std::io::Error),

    /// Failed to parse a line in mountinfo.
    #[error("Failed to parse mountinfo line {line_num}: {message}")]
    MountInfoParse {
        /// Line number (1-indexed) that failed to parse.
        line_num: usize,
        /// Description of the parse error.
        message: String,
    },

    /// Path resolves to a denied mount source.
    #[error("Path '{path}' resolves to denied mount source '{mount_source}'")]
    DeniedMountSource {
        /// The path that was requested.
        path: PathBuf,
        /// The mount source that triggered denial.
        mount_source: String,
    },

    /// Failed to resolve path to canonical form.
    #[error("Failed to resolve path '{path}': {source}")]
    PathResolution {
        /// The path that could not be resolved.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Path is not under any known mount point.
    #[error("Path '{path}' is not under any known mount")]
    NoMountFound {
        /// The path that has no associated mount.
        path: PathBuf,
    },

    /// Invalid denylist pattern.
    #[error("Invalid denylist pattern: {0}")]
    InvalidPattern(String),
}

/// Errors related to CA certificate operations.
///
/// These errors occur when generating ephemeral CAs, creating
/// domain certificates, or managing certificate files.
#[derive(Debug, Error)]
pub enum CaError {
    /// Failed to create temporary directory for CA files.
    #[error("Failed to create temp directory: {0}")]
    TempDir(#[source] std::io::Error),

    /// Failed to set file permissions.
    #[error("Failed to set permissions: {0}")]
    Permissions(#[source] std::io::Error),

    /// Failed to generate key pair.
    #[error("Failed to generate key pair: {0}")]
    KeyGeneration(String),

    /// Failed to generate certificate.
    #[error("Failed to generate certificate: {0}")]
    CertGeneration(String),

    /// Failed to serialize certificate or key.
    #[error("Failed to serialize certificate: {0}")]
    Serialization(String),

    /// Failed to write certificate or key file.
    #[error("Failed to write file: {0}")]
    WriteFile(#[source] std::io::Error),

    /// No domains specified for certificate generation.
    #[error("No domains specified for certificate")]
    NoDomains,

    /// Failed to read CA files.
    #[error("Failed to read file: {0}")]
    ReadFile(#[source] std::io::Error),

    /// Failed to sign certificate.
    #[error("Failed to sign certificate: {0}")]
    Signing(String),
}

/// Errors related to Bubblewrap command construction and execution.
#[derive(Debug, Error)]
pub enum BwrapError {
    /// Bubblewrap binary not found.
    #[error("Bubblewrap (bwrap) not found. Install with: apt install bubblewrap")]
    NotFound,

    /// Failed to spawn bwrap process.
    #[error("Failed to spawn bwrap: {0}")]
    SpawnFailed(#[source] std::io::Error),

    /// Bwrap process exited with error.
    #[error("Bubblewrap exited with code {code}: {stderr}")]
    ExitError {
        /// Exit code from bwrap.
        code: i32,
        /// Standard error output.
        stderr: String,
    },

    /// Invalid bind mount configuration.
    #[error("Invalid bind mount: {0}")]
    InvalidBindMount(String),

    /// Required path does not exist.
    #[error("Required path does not exist: {path}")]
    PathNotFound {
        /// The missing path.
        path: PathBuf,
    },

    /// Failed to wait for process.
    #[error("Failed to wait for sandbox process: {0}")]
    WaitFailed(#[source] std::io::Error),

    /// Failed to send signal.
    #[error("Failed to send signal to sandbox: {0}")]
    SignalFailed(#[source] nix::Error),
}

impl From<BwrapError> for SandboxError {
    fn from(err: BwrapError) -> Self {
        SandboxError::Bwrap(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_error_display() {
        let err = MountError::DeniedMountSource {
            path: PathBuf::from("/mnt/secure/data"),
            mount_source: "10.1.2.3:/secure-exports".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("/mnt/secure/data"));
        assert!(msg.contains("10.1.2.3:/secure-exports"));
    }

    #[test]
    fn test_ca_error_display() {
        let err = CaError::KeyGeneration("random number generator failed".to_string());
        let msg = err.to_string();
        assert!(msg.contains("random number generator failed"));
    }

    #[test]
    fn test_bwrap_error_display() {
        let err = BwrapError::ExitError {
            code: 1,
            stderr: "invalid option".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("code 1"));
        assert!(msg.contains("invalid option"));
    }

    #[test]
    fn test_sandbox_error_from_mount() {
        let mount_err = MountError::NoMountFound {
            path: PathBuf::from("/some/path"),
        };
        let sandbox_err: SandboxError = mount_err.into();
        assert!(matches!(sandbox_err, SandboxError::Mount(_)));
    }

    #[test]
    fn test_sandbox_error_from_ca() {
        let ca_err = CaError::NoDomains;
        let sandbox_err: SandboxError = ca_err.into();
        assert!(matches!(sandbox_err, SandboxError::Ca(_)));
    }
}
