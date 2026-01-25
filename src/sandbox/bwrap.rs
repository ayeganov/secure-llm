//! Bubblewrap sandbox construction and management.
//!
//! This module constructs and spawns Bubblewrap sandboxes with proper namespace
//! isolation, bind mounts, and environment variable injection.
//!
//! # Why Bubblewrap?
//!
//! Bubblewrap is a well-audited, minimal sandbox tool that uses Linux namespaces
//! without requiring root. It's the foundation of Flatpak and is battle-tested.
//!
//! # Namespace Isolation
//!
//! We use the following namespaces:
//! - **User namespace**: Unprivileged containment with UID/GID mapping
//! - **Mount namespace**: Isolated filesystem view
//! - **Network namespace**: Isolated network stack (created by netns module)
//! - **PID namespace**: Isolated process tree
//! - **UTS namespace**: Isolated hostname (required for custom hostname)
//!
//! # Critical: UID/GID Mapping
//!
//! When using `--unshare-user`, bwrap does NOT automatically map your host UID
//! into the namespace. Without explicit mapping, the process runs as `nobody`
//! (65534) and cannot access files owned by the host user.
//!
//! **Always pair `unshare_user()` with `map_current_user()`!**
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::sandbox::bwrap::BwrapBuilder;
//!
//! let builder = BwrapBuilder::new()
//!     .unshare_user()
//!     .map_current_user()  // CRITICAL!
//!     .unshare_pid()
//!     .bind_ro(Path::new("/usr"), Path::new("/usr"))
//!     .bind_rw(Path::new("/home/user/project"), Path::new("/home/user/project"))
//!     .setenv("PATH", "/usr/bin:/bin")
//!     .chdir(Path::new("/home/user/project"))
//!     .die_with_parent()
//!     .command(Path::new("/usr/bin/claude"), &["arg1".to_string()]);
//!
//! let cmd = builder.build();
//! ```

use super::error::{BwrapError, MountError};
use super::mounts::MountVerifier;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use tracing::{debug, info};

/// Canonical path where the CA bundle is mounted inside the sandbox.
///
/// This is the Debian/Ubuntu standard location. The bundle is also mounted
/// to other distro-specific paths, but this is the path that should be used
/// for environment variables like `SSL_CERT_FILE`.
pub const SANDBOX_CA_BUNDLE_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";

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
    /// Path to synthetic resolv.conf (avoids systemd-resolved 127.0.0.53 issue).
    pub resolv_conf_path: PathBuf,
    /// Path to proxy Unix socket on host (for bind-mounting into sandbox).
    ///
    /// When set, enables the rootless socket shim architecture:
    /// - The socket is bind-mounted into the sandbox at `/tmp/proxy.sock`
    /// - The secure-llm binary is bind-mounted at `/bin/secure-llm`
    /// - The entrypoint runs the shim in background and then the tool
    pub proxy_socket_path: Option<PathBuf>,
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

/// Builder for constructing Bubblewrap command lines.
pub struct BwrapBuilder {
    args: Vec<OsString>,
    env_vars: HashMap<String, String>,
}

impl BwrapBuilder {
    /// Create a new bwrap command builder.
    pub fn new() -> Self {
        Self {
            args: Vec::new(),
            env_vars: HashMap::new(),
        }
    }

    /// Add a raw argument to the command line.
    fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add user namespace isolation.
    ///
    /// **CRITICAL**: Must be paired with `map_current_user()` or the process
    /// will run as `nobody` (65534) and cannot access user files!
    pub fn unshare_user(self) -> Self {
        self.arg("--unshare-user")
    }

    /// Map the current host UID/GID into the user namespace.
    ///
    /// **The UID/GID Mapping Problem**: When you call `--unshare-user` to create
    /// a new user namespace, bwrap does NOT automatically map your host UID into it.
    /// Without explicit mapping, the process runs as the "overflow" user (nobody/65534).
    ///
    /// **The Symptom**: `Permission denied` when writing to work_dir or reading ~/.config,
    /// because those files are owned by your host UID (e.g., 1000) but the sandbox
    /// process is running as 65534.
    ///
    /// **The Fix**: Tell bwrap what UID/GID to use inside the namespace.
    pub fn map_current_user(self) -> Self {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        self.arg("--uid")
            .arg(uid.to_string())
            .arg("--gid")
            .arg(gid.to_string())
    }

    /// Set specific UID/GID inside the sandbox.
    ///
    /// Useful for privilege dropping when running as root - pass the
    /// target user's UID/GID to run as that user inside the sandbox.
    ///
    /// When running via sudo, use `SUDO_UID` and `SUDO_GID` environment
    /// variables to get the original user's IDs.
    pub fn uid_gid(self, uid: u32, gid: u32) -> Self {
        self.arg("--uid")
            .arg(uid.to_string())
            .arg("--gid")
            .arg(gid.to_string())
    }

    /// Add PID namespace isolation with /proc mount.
    pub fn unshare_pid(self) -> Self {
        self.arg("--unshare-pid")
    }

    /// Create a new (isolated) network namespace.
    ///
    /// This creates a completely isolated network with no connectivity.
    /// To join an existing network namespace (e.g., for proxy routing),
    /// wrap the bwrap command with `ip netns exec <name>`.
    pub fn unshare_net(self) -> Self {
        self.arg("--unshare-net")
    }

    /// Create a new (isolated) UTS namespace.
    ///
    /// This isolates the hostname and domain name. Required when using
    /// `hostname()` to set a custom hostname inside the sandbox.
    pub fn unshare_uts(self) -> Self {
        self.arg("--unshare-uts")
    }

    /// Add read-only bind mount.
    pub fn bind_ro(self, src: &Path, dest: &Path) -> Self {
        self.arg("--ro-bind").arg(src).arg(dest)
    }

    /// Add read-only bind mount, skipping if source doesn't exist.
    pub fn bind_ro_try(self, src: &Path, dest: &Path) -> Self {
        self.arg("--ro-bind-try").arg(src).arg(dest)
    }

    /// Add read-write bind mount.
    pub fn bind_rw(self, src: &Path, dest: &Path) -> Self {
        self.arg("--bind").arg(src).arg(dest)
    }

    /// Add read-write bind mount, skipping if source doesn't exist.
    pub fn bind_rw_try(self, src: &Path, dest: &Path) -> Self {
        self.arg("--bind-try").arg(src).arg(dest)
    }

    /// Add tmpfs mount at destination.
    pub fn tmpfs(self, dest: &Path) -> Self {
        self.arg("--tmpfs").arg(dest)
    }

    /// Add minimal /dev devices.
    ///
    /// Creates a new devtmpfs with only null, zero, urandom, etc.
    pub fn dev_minimal(self) -> Self {
        self.arg("--dev").arg("/dev")
    }

    /// Add /proc mount (requires PID namespace).
    pub fn proc_mount(self, dest: &Path) -> Self {
        self.arg("--proc").arg(dest)
    }

    /// Set working directory inside sandbox.
    pub fn chdir(self, path: &Path) -> Self {
        self.arg("--chdir").arg(path)
    }

    /// Set environment variable inside sandbox.
    pub fn setenv(mut self, key: &str, value: &str) -> Self {
        self.env_vars.insert(key.to_string(), value.to_string());
        self.arg("--setenv").arg(key).arg(value)
    }

    /// Unset environment variable inside sandbox.
    pub fn unsetenv(self, key: &str) -> Self {
        self.arg("--unsetenv").arg(key)
    }

    /// Set hostname inside sandbox.
    pub fn hostname(self, name: &str) -> Self {
        self.arg("--hostname").arg(name)
    }

    /// Die when parent process exits.
    ///
    /// This ensures the sandbox cleans up properly if secure-llm exits.
    pub fn die_with_parent(self) -> Self {
        self.arg("--die-with-parent")
    }

    /// Create a new session (detach from controlling terminal).
    pub fn new_session(self) -> Self {
        self.arg("--new-session")
    }

    /// Add standard system mounts (read-only).
    ///
    /// **Critical DNS Note**: We use a synthetic resolv.conf instead of the host's.
    /// On modern Linux (Ubuntu/Fedora with systemd-resolved), `/etc/resolv.conf`
    /// points to `127.0.0.53`. Inside our network namespace, this address doesn't
    /// exist, causing DNS lookups to hang for 30 seconds and then fail.
    ///
    /// # Arguments
    ///
    /// * `resolv_conf` - Path to synthetic resolv.conf with real DNS servers
    pub fn standard_system_mounts(self, resolv_conf: &Path) -> Self {
        self
            // Basic system directories (read-only)
            .bind_ro(Path::new("/usr"), Path::new("/usr"))
            .bind_ro_try(Path::new("/lib"), Path::new("/lib"))
            .bind_ro_try(Path::new("/lib64"), Path::new("/lib64"))
            .bind_ro_try(Path::new("/bin"), Path::new("/bin"))
            .bind_ro_try(Path::new("/sbin"), Path::new("/sbin"))
            // Essential files - NOTE: resolv.conf is SYNTHETIC, not from host!
            .bind_ro(resolv_conf, Path::new("/etc/resolv.conf"))
            .bind_ro_try(Path::new("/etc/hosts"), Path::new("/etc/hosts"))
            .bind_ro_try(Path::new("/etc/passwd"), Path::new("/etc/passwd"))
            .bind_ro_try(Path::new("/etc/group"), Path::new("/etc/group"))
            .bind_ro_try(Path::new("/etc/nsswitch.conf"), Path::new("/etc/nsswitch.conf"))
            .bind_ro_try(Path::new("/etc/localtime"), Path::new("/etc/localtime"))
            // Minimal /dev
            .dev_minimal()
            // Temp directories
            .tmpfs(Path::new("/tmp"))
            .tmpfs(Path::new("/var/tmp"))
    }

    /// Add CA certificate bind mounts for system-wide trust.
    ///
    /// **Critical CA Note**: The `ca_bundle_path` should point to a COMBINED bundle
    /// containing both the host's CA certificates AND our ephemeral CA.
    /// If we only mount our ephemeral CA, the sandbox will only trust our proxy
    /// and break verification of signed artifacts that don't go through the proxy.
    ///
    /// Use `EphemeralCa::create_combined_bundle()` to generate this file.
    pub fn ca_certificate_mounts(self, ca_bundle_path: &Path) -> Self {
        self
            // Debian/Ubuntu location (canonical path used by SANDBOX_CA_BUNDLE_PATH)
            .bind_ro(ca_bundle_path, Path::new(SANDBOX_CA_BUNDLE_PATH))
            // RHEL/Fedora location
            .bind_ro(ca_bundle_path, Path::new("/etc/pki/tls/certs/ca-bundle.crt"))
            // Generic location some tools use
            .bind_ro(ca_bundle_path, Path::new("/etc/ssl/cert.pem"))
    }

    /// Add user config directories (read-only).
    ///
    /// These are needed for tool configurations like .gitconfig, .npmrc, etc.
    pub fn user_config_mounts(self, home: &Path) -> Self {
        let config_dir = home.join(".config");
        self.bind_ro_try(&config_dir, &config_dir)
            .bind_ro_try(&home.join(".gitconfig"), &home.join(".gitconfig"))
            .bind_ro_try(&home.join(".npmrc"), &home.join(".npmrc"))
            .bind_ro_try(&home.join(".cargo"), &home.join(".cargo"))
    }

    /// Set the command to execute inside the sandbox.
    ///
    /// This must be called last before `build()`.
    pub fn command(mut self, cmd: &Path, args: &[String]) -> Self {
        self.args.push("--".into());
        self.args.push(cmd.as_os_str().to_owned());
        for arg in args {
            self.args.push(arg.into());
        }
        self
    }

    /// Build the final Command (but don't execute it).
    pub fn build(self) -> Command {
        let mut cmd = Command::new("bwrap");
        for arg in &self.args {
            cmd.arg(arg);
        }
        cmd
    }

    /// Get the command line as a string (for debugging/logging).
    pub fn to_command_line(&self) -> String {
        let mut parts = vec!["bwrap".to_string()];
        for arg in &self.args {
            let s = arg.to_string_lossy();
            // Quote arguments containing spaces
            if s.contains(' ') || s.contains('"') {
                parts.push(format!("'{}'", s.replace('\'', "'\\''")));
            } else {
                parts.push(s.into_owned());
            }
        }
        parts.join(" ")
    }
}

impl Default for BwrapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level sandbox launcher.
///
/// Combines mount verification with Bubblewrap command construction.
pub struct SandboxLauncher {
    mount_verifier: MountVerifier,
}

impl SandboxLauncher {
    /// Create a new launcher with a mount verifier.
    pub fn new(mount_verifier: MountVerifier) -> Self {
        Self { mount_verifier }
    }

    /// Verify paths and launch the sandbox.
    ///
    /// # Returns
    ///
    /// A `SandboxHandle` to manage the running sandbox.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Mount verification fails for any path
    /// - Bubblewrap cannot be spawned
    #[must_use = "sandbox handle must be used to wait for or manage the sandbox"]
    pub fn launch(&self, config: SandboxConfig) -> Result<SandboxHandle, MountError> {
        info!("Launching sandbox for tool: {:?}", config.tool_binary);

        // Verify all bind mount paths
        let mut paths_to_verify: Vec<PathBuf> = config.bind_rw.iter().map(|b| b.src.clone()).collect();
        paths_to_verify.extend(config.bind_ro.iter().map(|b| b.src.clone()));
        paths_to_verify.push(config.work_dir.clone());

        // Verify each path (handles non-existent paths via parent traversal)
        for path in &paths_to_verify {
            if path.exists() || path.parent().map(|p| p.exists()).unwrap_or(false) {
                // Only verify paths that exist or have existing parents
                // Skip verification for standard system paths like /usr, /lib
                if !path.starts_with("/usr")
                    && !path.starts_with("/lib")
                    && !path.starts_with("/bin")
                    && !path.starts_with("/sbin")
                    && !path.starts_with("/etc")
                    && !path.starts_with("/dev")
                    && !path.starts_with("/proc")
                {
                    self.mount_verifier.verify_path(path)?;
                }
            }
        }

        // Build the bwrap command
        let mut builder = BwrapBuilder::new()
            .unshare_user()
            .map_current_user() // CRITICAL: Without this, process runs as nobody!
            .unshare_pid()
            .unshare_uts() // Required for custom hostname
            .proc_mount(Path::new("/proc"))
            .standard_system_mounts(&config.resolv_conf_path)
            .ca_certificate_mounts(&config.ca_bundle_path)
            .chdir(&config.work_dir)
            .die_with_parent()
            .hostname("sandbox");

        // Network isolation - always use --unshare-net for rootless operation
        // The egress shim inside the sandbox bridges traffic to the host via Unix socket
        builder = builder.unshare_net();

        // Add read-only bind mounts
        for mount in &config.bind_ro {
            if mount.src.exists() {
                builder = builder.bind_ro(&mount.src, &mount.dest);
            }
        }

        // Add read-write bind mounts
        for mount in &config.bind_rw {
            if mount.src.exists() {
                builder = builder.bind_rw(&mount.src, &mount.dest);
            }
        }

        // Add work directory as read-write
        builder = builder.bind_rw(&config.work_dir, &config.work_dir);

        // Add user home for config files
        if let Some(home) = dirs::home_dir() {
            builder = builder.user_config_mounts(&home);
        }

        // Set environment variables
        for (key, value) in &config.env {
            builder = builder.setenv(key, value);
        }

        // Add any extra flags
        for flag in &config.extra_flags {
            builder = builder.arg(flag);
        }

        // Configure rootless socket shim if enabled
        if let Some(ref socket_path) = config.proxy_socket_path {
            // Bind-mount the proxy socket into the sandbox
            builder = builder.bind_rw(socket_path, Path::new("/tmp/proxy.sock"));

            // Bind-mount the secure-llm binary (ourselves) into the sandbox
            // This allows us to run the shim inside the sandbox
            // Note: Can't use /bin since it's mounted read-only, so we use /opt
            let self_exe = std::env::current_exe().map_err(|e| MountError::PathResolution {
                path: PathBuf::from("/proc/self/exe"),
                source: e,
            })?;
            builder = builder.bind_ro(&self_exe, Path::new("/opt/secure-llm"));

            // The entrypoint runs the shim in background, then execs the tool
            // Format: /bin/sh -c "/opt/secure-llm internal-shim /tmp/proxy.sock & exec <tool> <args>"
            let tool_cmd = if config.tool_args.is_empty() {
                config.tool_binary.display().to_string()
            } else {
                format!(
                    "{} {}",
                    config.tool_binary.display(),
                    config.tool_args.join(" ")
                )
            };
            let shell_cmd = format!(
                "/opt/secure-llm internal-shim /tmp/proxy.sock & exec {}",
                tool_cmd
            );

            builder = builder.command(Path::new("/bin/sh"), &["-c".to_string(), shell_cmd]);
        } else {
            // Direct tool execution (no shim)
            builder = builder.command(&config.tool_binary, &config.tool_args);
        }

        debug!("Bwrap command: {}", builder.to_command_line());

        // Spawn the sandbox
        let mut cmd = builder.build();

        // Inherit stdin/stdout/stderr for interactive tools
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let child = cmd.spawn().map_err(|e| MountError::PathResolution {
            path: PathBuf::from("bwrap"),
            source: e,
        })?;

        let pid = child.id();
        info!("Sandbox started with PID: {}", pid);

        Ok(SandboxHandle {
            child,
            pid,
            proxy_socket_path: config.proxy_socket_path,
        })
    }
}

/// Handle to a running sandbox.
pub struct SandboxHandle {
    child: Child,
    /// PID of the bwrap process.
    pub pid: u32,
    /// Path to proxy Unix socket (if using shim architecture).
    pub proxy_socket_path: Option<PathBuf>,
}

impl SandboxHandle {
    /// Wait for the sandbox to exit.
    pub fn wait(&mut self) -> Result<ExitStatus, BwrapError> {
        self.child.wait().map_err(BwrapError::WaitFailed)
    }

    /// Send a signal to the sandboxed process.
    pub fn signal(&self, signal: nix::sys::signal::Signal) -> Result<(), BwrapError> {
        use nix::sys::signal::kill;
        use nix::unistd::Pid;

        kill(Pid::from_raw(self.pid as i32), signal).map_err(BwrapError::SignalFailed)
    }

    /// Kill the sandbox (SIGKILL).
    pub fn kill(&mut self) -> Result<(), BwrapError> {
        self.child.kill().map_err(BwrapError::SpawnFailed)
    }

    /// Check if the sandbox is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Get the exit status if available without blocking.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, BwrapError> {
        self.child.try_wait().map_err(BwrapError::WaitFailed)
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
///
/// Supported placeholders:
/// - `${SANDBOX_CA_CERT}` - Path to the CA certificate
/// - `${SANDBOX_WORK_DIR}` - Working directory inside sandbox
/// - `${SANDBOX_PROXY}` - Proxy address (http://host:port)
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

/// Check if bwrap is available on the system.
pub fn bwrap_available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get bwrap version string.
pub fn bwrap_version() -> Option<String> {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bwrap_builder_basic() {
        let builder = BwrapBuilder::new()
            .unshare_user()
            .map_current_user()
            .command(Path::new("/usr/bin/echo"), &["hello".to_string()]);

        let cmd_line = builder.to_command_line();
        assert!(cmd_line.contains("--unshare-user"));
        assert!(cmd_line.contains("--uid"));
        assert!(cmd_line.contains("--gid"));
        assert!(cmd_line.contains("/usr/bin/echo"));
        assert!(cmd_line.contains("hello"));
    }

    #[test]
    fn test_bwrap_builder_bind_mounts() {
        let builder = BwrapBuilder::new()
            .bind_ro(Path::new("/usr"), Path::new("/usr"))
            .bind_rw(Path::new("/home/user"), Path::new("/home/user"))
            .command(Path::new("/bin/sh"), &[]);

        let cmd_line = builder.to_command_line();
        assert!(cmd_line.contains("--ro-bind /usr /usr"));
        assert!(cmd_line.contains("--bind /home/user /home/user"));
    }

    #[test]
    fn test_bwrap_builder_environment() {
        let builder = BwrapBuilder::new()
            .setenv("FOO", "bar")
            .setenv("PATH", "/usr/bin:/bin")
            .command(Path::new("/bin/sh"), &[]);

        let cmd_line = builder.to_command_line();
        assert!(cmd_line.contains("--setenv FOO bar"));
        assert!(cmd_line.contains("--setenv PATH /usr/bin:/bin"));
    }

    #[test]
    fn test_bind_mount_same() {
        let mount = BindMount::same(PathBuf::from("/home/user/project"));
        assert_eq!(mount.src, mount.dest);
    }

    #[test]
    fn test_bind_mount_different() {
        let mount = BindMount::new(
            PathBuf::from("/home/user/project"),
            PathBuf::from("/workspace"),
        );
        assert_ne!(mount.src, mount.dest);
        assert_eq!(mount.src, PathBuf::from("/home/user/project"));
        assert_eq!(mount.dest, PathBuf::from("/workspace"));
    }

    #[test]
    fn test_expand_env_vars() {
        let mut env = HashMap::new();
        env.insert(
            "SSL_CERT_FILE".to_string(),
            "${SANDBOX_CA_CERT}".to_string(),
        );
        env.insert(
            "WORK_DIR".to_string(),
            "${SANDBOX_WORK_DIR}/subdir".to_string(),
        );
        env.insert(
            "HTTP_PROXY".to_string(),
            "${SANDBOX_PROXY}".to_string(),
        );

        let context = EnvContext {
            ca_cert_path: PathBuf::from("/tmp/ca.crt"),
            work_dir: PathBuf::from("/home/user/project"),
            proxy_addr: "http://10.200.0.1:8080".to_string(),
        };

        let expanded = expand_env_vars(&env, &context);

        assert_eq!(expanded.get("SSL_CERT_FILE").unwrap(), "/tmp/ca.crt");
        assert_eq!(
            expanded.get("WORK_DIR").unwrap(),
            "/home/user/project/subdir"
        );
        assert_eq!(expanded.get("HTTP_PROXY").unwrap(), "http://10.200.0.1:8080");
    }

    #[test]
    fn test_bwrap_available() {
        // This test just ensures the function doesn't panic
        let _ = bwrap_available();
    }

    #[test]
    fn test_standard_system_mounts() {
        let temp_dir = tempfile::tempdir().unwrap();
        let resolv_conf = temp_dir.path().join("resolv.conf");
        std::fs::write(&resolv_conf, "nameserver 8.8.8.8").unwrap();

        let builder = BwrapBuilder::new()
            .standard_system_mounts(&resolv_conf)
            .command(Path::new("/bin/sh"), &[]);

        let cmd_line = builder.to_command_line();

        // Check that essential paths are mounted
        assert!(cmd_line.contains("--ro-bind") || cmd_line.contains("--ro-bind-try"));
        assert!(cmd_line.contains("/usr"));
        assert!(cmd_line.contains("--dev /dev"));
        assert!(cmd_line.contains("--tmpfs /tmp"));
    }

    #[test]
    fn test_ca_certificate_mounts() {
        let temp_dir = tempfile::tempdir().unwrap();
        let ca_bundle = temp_dir.path().join("ca-bundle.crt");
        std::fs::write(&ca_bundle, "fake ca bundle").unwrap();

        let builder = BwrapBuilder::new()
            .ca_certificate_mounts(&ca_bundle)
            .command(Path::new("/bin/sh"), &[]);

        let cmd_line = builder.to_command_line();

        // Check that CA is mounted to standard locations
        assert!(cmd_line.contains("/etc/ssl/certs/ca-certificates.crt"));
        assert!(cmd_line.contains("/etc/pki/tls/certs/ca-bundle.crt"));
        assert!(cmd_line.contains("/etc/ssl/cert.pem"));
    }
}
