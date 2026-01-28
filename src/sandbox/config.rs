//! Configuration types for the Bubblewrap sandbox.

use std::collections::HashMap;
use std::path::PathBuf;

/// Canonical path where the CA bundle is mounted inside the sandbox.
pub const SANDBOX_CA_BUNDLE_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Default maximum number of port bridge slots.
pub const DEFAULT_MAX_PORT_BRIDGES: u8 = 8;

/// Configuration for a Bubblewrap sandbox.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Tool binary to execute.
    pub tool_binary: PathBuf,
    /// Arguments to pass to tool.
    pub tool_args: Vec<String>,
    /// Working directory inside sandbox.
    pub work_dir: PathBuf,
    /// Environment variables to set.
    pub env: HashMap<String, String>,
    /// Paths to bind read-write.
    pub bind_rw: Vec<BindMount>,
    /// Paths to bind read-only.
    pub bind_ro: Vec<BindMount>,
    /// Path to combined CA bundle (host CAs + ephemeral CA).
    pub ca_bundle_path: PathBuf,
    /// Path to synthetic resolv.conf.
    pub resolv_conf_path: PathBuf,
    /// Path to proxy Unix socket on host.
    pub proxy_socket_path: Option<PathBuf>,
    /// Path to portbridge socket directory on host (for port bridging).
    pub portbridge_dir: Option<PathBuf>,
    /// Maximum number of port bridge slots.
    pub max_port_bridges: u8,
    /// Additional bwrap flags.
    pub extra_flags: Vec<String>,
}

/// A bind mount specification.
#[derive(Debug, Clone)]
pub struct BindMount {
    /// Source path on host.
    pub src: PathBuf,
    /// Destination path in sandbox (defaults to same as src).
    pub dest: PathBuf,
}

impl BindMount {
    /// Create a bind mount where source and destination are the same.
    pub fn same(path: PathBuf) -> Self {
        Self {
            src: path.clone(),
            dest: path,
        }
    }

    /// Create a bind mount with different source and destination.
    pub fn new(src: PathBuf, dest: PathBuf) -> Self {
        Self { src, dest }
    }
}

/// Context for expanding environment variable placeholders.
#[derive(Debug, Clone)]
pub struct EnvContext {
    /// Path to CA certificate for `${SANDBOX_CA_CERT}`.
    pub ca_cert_path: PathBuf,
    /// Working directory for `${SANDBOX_WORK_DIR}`.
    pub work_dir: PathBuf,
    /// Proxy address for `${SANDBOX_PROXY}`.
    pub proxy_addr: String,
}

/// Expand environment variable placeholders in profile values.
pub fn expand_env_vars(
    env: &HashMap<String, String>,
    context: &EnvContext,
) -> HashMap<String, String> {
    env.iter()
        .map(|(k, v)| {
            let expanded = v
                .replace("${SANDBOX_CA_CERT}", &context.ca_cert_path.to_string_lossy())
                .replace("${SANDBOX_WORK_DIR}", &context.work_dir.to_string_lossy())
                .replace("${SANDBOX_PROXY}", &context.proxy_addr);
            (k.clone(), expanded)
        })
        .collect()
}
