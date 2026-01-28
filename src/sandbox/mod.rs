//! Sandbox isolation module for secure-llm.
//!
//! This module provides Bubblewrap-based process isolation with:
//! - Rootless network isolation via Unix socket shim
//! - Mount namespace with verified bind mounts
//! - Ephemeral CA certificate injection for TLS interception
//! - Environment variable setup for the sandboxed tool
//!
//! # Security Model
//!
//! The sandbox interior is **untrusted**. Code inside can:
//! - Attempt symlink attacks to access sensitive files
//! - Try to bypass network isolation
//! - Attempt to escape mount namespace restrictions
//!
//! Our job is to prevent all of these through:
//! - Path canonicalization before mount verification
//! - Mount source denylist checking
//! - Network isolation with proxy-only egress
//! - Ephemeral CA with automatic cleanup
//!
//! # Critical Security Notes
//!
//! 1. **UID/GID Mapping**: Always use `BwrapBuilder::map_current_user()` with
//!    `unshare_user()`. Without it, the process runs as `nobody` (65534).
//!
//! 2. **Combined CA Bundle**: Use `EphemeralCa::create_combined_bundle()` to
//!    include both host CAs and the ephemeral CA. Don't replace the system
//!    trust store with only the ephemeral CA.
//!
//! 3. **Synthetic resolv.conf**: The sandbox needs its own DNS config.
//!    The host's `/etc/resolv.conf` (often `127.0.0.53` on systemd-resolved
//!    systems) doesn't work inside the sandbox.
//!
//! 4. **Non-existent Paths**: The mount verifier handles paths that don't exist
//!    yet by verifying the nearest existing ancestor.
//!
//! # Architecture (Rootless Socket Shim)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Sandbox (rootless)                       │
//! │                                                             │
//! │   ┌──────────────┐         ┌───────────────────────────┐   │
//! │   │  Tool        │ HTTP    │     EgressShim            │   │
//! │   │  (claude,    │ PROXY   │  TCP 127.0.0.1:8080       │   │
//! │   │   cursor)    │────────►│         │                 │   │
//! │   └──────────────┘         │         ▼                 │   │
//! │                            │  /tmp/proxy.sock ─────────┼───┼──┐
//! │                            └───────────────────────────┘   │  │
//! └─────────────────────────────────────────────────────────────┘  │
//!                                                                  │
//! ┌────────────────────────────────────────────────────────────────┼──┐
//! │                     Host                                       │  │
//! │                                                                │  │
//! │   ┌───────────────────────────────────────────────────────┐    │  │
//! │   │               ProxyServer                             │◄───┘  │
//! │   │           Unix Socket Listener                        │       │
//! │   │                    │                                  │       │
//! │   │                    ▼                                  │       │
//! │   │              (to internet)                            │       │
//! │   └───────────────────────────────────────────────────────┘       │
//! └────────────────────────────────────────────────────────────────────┘
//! ```

pub mod builder;
pub mod bwrap;
pub mod ca;
pub mod cleanup;
pub mod config;
pub mod error;
pub mod handle;
pub mod mounts;

// Re-export main types for convenience
pub use builder::BwrapBuilder;
pub use bwrap::{bwrap_available, bwrap_version, SandboxLauncher};
pub use config::{
    expand_env_vars, BindMount, EnvContext, SandboxConfig, SANDBOX_CA_BUNDLE_PATH,
    DEFAULT_MAX_PORT_BRIDGES,
};
pub use handle::SandboxHandle;
pub use ca::{find_host_ca_bundle, DomainCertificate, EphemeralCa, HOST_CA_BUNDLES};
pub use cleanup::{cleanup_stale_resources, list_stale_resources, StaleResources};
pub use error::{BwrapError, CaError, MountError, SandboxError};
pub use mounts::{MountInfo, MountPattern, MountTable, MountVerifier};
