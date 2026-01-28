//! High-level Bubblewrap sandbox launcher.
//!
//! This module orchestrates the construction and spawning of Bubblewrap sandboxes.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::{debug, info};

pub use super::builder::BwrapBuilder;
use super::config::SandboxConfig;
use super::handle::SandboxHandle;
use super::error::MountError;
use super::mounts::MountVerifier;

/// High-level sandbox launcher.
pub struct SandboxLauncher {
    mount_verifier: MountVerifier,
}

impl SandboxLauncher {
    /// Create a new launcher with a mount verifier.
    pub fn new(mount_verifier: MountVerifier) -> Self {
        Self { mount_verifier }
    }

    /// Verify paths and launch the sandbox.
    #[must_use = "sandbox handle must be used to wait for or manage the sandbox"]
    pub fn launch(&self, config: SandboxConfig) -> Result<SandboxHandle, MountError> {
        info!("Launching sandbox for tool: {:?}", config.tool_binary);

        // Verify all bind mount paths
        let mut paths_to_verify: Vec<PathBuf> = config.bind_rw.iter().map(|b| b.src.clone()).collect();
        paths_to_verify.extend(config.bind_ro.iter().map(|b| b.src.clone()));
        paths_to_verify.push(config.work_dir.clone());

        for path in &paths_to_verify {
            if (path.exists() || path.parent().map(|p| p.exists()).unwrap_or(false))
                && !path.starts_with("/usr")
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

        let mut builder = BwrapBuilder::new()
            .unshare_user()
            .map_current_user()
            .unshare_pid()
            .unshare_uts()
            .proc_mount(Path::new("/proc"))
            .standard_system_mounts(&config.resolv_conf_path)
            .ca_certificate_mounts(&config.ca_bundle_path)
            .chdir(&config.work_dir)
            .die_with_parent()
            .hostname("sandbox");

        builder = builder.unshare_net();

        for mount in &config.bind_ro {
            if mount.src.exists() {
                builder = builder.bind_ro(&mount.src, &mount.dest);
            }
        }

        for mount in &config.bind_rw {
            if mount.src.exists() {
                builder = builder.bind_rw(&mount.src, &mount.dest);
            }
        }

        builder = builder.bind_rw(&config.work_dir, &config.work_dir);

        if let Some(home) = dirs::home_dir() {
            builder = builder.user_config_mounts(&home);
        }

        for (key, value) in &config.env {
            builder = builder.setenv(key, value);
        }

        for flag in &config.extra_flags {
            builder = builder.arg(flag);
        }

        if let Some(ref socket_path) = config.proxy_socket_path {
            builder = builder.bind_rw(socket_path, Path::new("/tmp/proxy.sock"));

            let self_exe = std::env::current_exe().map_err(|e| MountError::PathResolution {
                path: PathBuf::from("/proc/self/exe"),
                source: e,
            })?;
            builder = builder.bind_ro(&self_exe, Path::new("/opt/secure-llm"));

            // Bind-mount portbridge directory if configured
            if let Some(ref portbridge_dir) = config.portbridge_dir {
                builder = builder.bind_rw(portbridge_dir, Path::new("/tmp/portbridge"));
            }

            let tool_cmd = if config.tool_args.is_empty() {
                config.tool_binary.display().to_string()
            } else {
                format!(
                    "{} {}",
                    config.tool_binary.display(),
                    config.tool_args.join(" ")
                )
            };

            // Build shell command with optional reverse shim
            let shell_cmd = if config.portbridge_dir.is_some() {
                format!(
                    "/opt/secure-llm internal-reverse-shim /tmp/portbridge {} & \
                     /opt/secure-llm internal-shim /tmp/proxy.sock & \
                     exec {}",
                    config.max_port_bridges, tool_cmd
                )
            } else {
                format!(
                    "/opt/secure-llm internal-shim /tmp/proxy.sock & exec {}",
                    tool_cmd
                )
            };

            builder = builder.command(Path::new("/bin/sh"), &["-c".to_string(), shell_cmd]);
        } else {
            builder = builder.command(&config.tool_binary, &config.tool_args);
        }

        debug!("Bwrap command: {}", builder.to_command_line());

        let mut cmd = builder.build();
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