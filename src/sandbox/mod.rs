//! Sandbox isolation module for secure-llm.
//!
//! This module provides Bubblewrap-based process isolation with:
//! - Network namespace isolation (veth pair for traffic routing)
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
//! - Network namespace isolation with veth routing
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
//! 3. **Synthetic resolv.conf**: The network namespace needs its own DNS config.
//!    The host's `/etc/resolv.conf` (often `127.0.0.53` on systemd-resolved
//!    systems) doesn't work inside the namespace.
//!
//! 4. **Non-existent Paths**: The mount verifier handles paths that don't exist
//!    yet by verifying the nearest existing ancestor.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │                      Host Environment                          │
//! │                                                                │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │                    Bubblewrap Sandbox                     │  │
//! │  │  ├── User Namespace (mapped UID/GID)                     │  │
//! │  │  ├── Mount Namespace (verified bind mounts)              │  │
//! │  │  ├── PID Namespace (isolated process tree)               │  │
//! │  │  ├── Network Namespace (veth pair)                       │  │
//! │  │  │       └── veth-sandbox (10.200.0.2) ─────┐            │  │
//! │  │  ├── CA: /etc/ssl/certs/ca-certificates.crt │            │  │
//! │  │  ├── DNS: synthetic /etc/resolv.conf        │            │  │
//! │  │  └── Process: IDE/Agent                     │            │  │
//! │  └───────────────────────────────────────────│─┘            │  │
//! │                                              │               │  │
//! │                                              │               │  │
//! │  veth-host (10.200.0.1) ◄────────────────────┘               │  │
//! │       │                                                      │  │
//! │       ▼                                                      │  │
//! │  ┌─────────┐                                                 │  │
//! │  │  Proxy  │ ──► (to internet via host network)              │  │
//! │  │ :8080   │                                                 │  │
//! │  └─────────┘                                                 │  │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example Usage
//!
//! ```ignore
//! use secure_llm::sandbox::{
//!     cleanup::cleanup_stale_resources,
//!     ca::{EphemeralCa, find_host_ca_bundle},
//!     netns::{NetworkNamespace, NetnsConfig},
//!     mounts::MountVerifier,
//!     bwrap::{SandboxConfig, SandboxLauncher, BindMount, expand_env_vars, EnvContext},
//! };
//!
//! // 1. Clean up any stale resources from crashed sessions
//! cleanup_stale_resources();
//!
//! // 2. Generate ephemeral CA
//! let ca = EphemeralCa::generate()?;
//!
//! // 3. Create combined CA bundle (host + ephemeral)
//! let host_bundle = find_host_ca_bundle()
//!     .unwrap_or(Path::new("/etc/ssl/certs/ca-certificates.crt"));
//! let combined_bundle = ca.create_combined_bundle(host_bundle)?;
//!
//! // 4. Create network namespace
//! let netns = NetworkNamespace::create(NetnsConfig::default())?;
//!
//! // 5. Create mount verifier with denylist
//! let mount_verifier = MountVerifier::new(&config.filesystem.denylist)?;
//!
//! // 6. Build sandbox configuration
//! let sandbox_config = SandboxConfig {
//!     tool_binary: PathBuf::from("claude"),
//!     tool_args: vec![],
//!     work_dir: std::env::current_dir()?,
//!     env: expand_env_vars(&profile.environment, &EnvContext {
//!         ca_cert_path: combined_bundle.clone(),
//!         work_dir: work_dir.clone(),
//!         proxy_addr: netns.proxy_url().to_string(),
//!     }),
//!     ca_bundle_path: combined_bundle,
//!     resolv_conf_path: netns.resolv_conf_path.clone(),
//!     netns_path: Some(netns.path().to_path_buf()),
//!     bind_rw: vec![BindMount::same(work_dir)],
//!     bind_ro: vec![],
//!     extra_flags: vec![],
//! };
//!
//! // 7. Launch sandbox
//! let launcher = SandboxLauncher::new(mount_verifier);
//! let mut handle = launcher.launch(sandbox_config)?;
//!
//! // 8. Wait for sandbox to exit
//! let status = handle.wait()?;
//! ```

pub mod bwrap;
pub mod ca;
pub mod cleanup;
pub mod error;
pub mod mounts;
pub mod netns;

// Re-export main types for convenience
pub use bwrap::{
    bwrap_available, bwrap_version, expand_env_vars, BindMount, BwrapBuilder, EnvContext,
    SandboxConfig, SandboxHandle, SandboxLauncher,
};
pub use ca::{find_host_ca_bundle, DomainCertificate, EphemeralCa, HOST_CA_BUNDLES};
pub use cleanup::{cleanup_stale_resources, list_stale_resources, StaleResources};
pub use error::{BwrapError, CaError, MountError, NetnsError, SandboxError};
pub use mounts::{MountInfo, MountPattern, MountTable, MountVerifier};
pub use netns::{list_secure_llm_namespaces, namespace_exists, NetnsConfig, NetworkNamespace};
