//! Builder for constructing Bubblewrap command lines.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use super::config::SANDBOX_CA_BUNDLE_PATH;

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
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add user namespace isolation.
    pub fn unshare_user(self) -> Self {
        self.arg("--unshare-user")
    }

    /// Map the current host UID/GID into the user namespace.
    pub fn map_current_user(self) -> Self {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        self.arg("--uid")
            .arg(uid.to_string())
            .arg("--gid")
            .arg(gid.to_string())
    }

    /// Set specific UID/GID inside the sandbox.
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
    pub fn unshare_net(self) -> Self {
        self.arg("--unshare-net")
    }

    /// Create a new (isolated) UTS namespace.
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
    pub fn die_with_parent(self) -> Self {
        self.arg("--die-with-parent")
    }

    /// Create a new session (detach from controlling terminal).
    pub fn new_session(self) -> Self {
        self.arg("--new-session")
    }

    /// Add standard system mounts (read-only).
    pub fn standard_system_mounts(self, resolv_conf: &Path) -> Self {
        self
            .bind_ro(Path::new("/usr"), Path::new("/usr"))
            .bind_ro_try(Path::new("/lib"), Path::new("/lib"))
            .bind_ro_try(Path::new("/lib64"), Path::new("/lib64"))
            .bind_ro_try(Path::new("/bin"), Path::new("/bin"))
            .bind_ro_try(Path::new("/sbin"), Path::new("/sbin"))
            .bind_ro(resolv_conf, Path::new("/etc/resolv.conf"))
            .bind_ro_try(Path::new("/etc/hosts"), Path::new("/etc/hosts"))
            .bind_ro_try(Path::new("/etc/passwd"), Path::new("/etc/passwd"))
            .bind_ro_try(Path::new("/etc/group"), Path::new("/etc/group"))
            .bind_ro_try(Path::new("/etc/nsswitch.conf"), Path::new("/etc/nsswitch.conf"))
            .bind_ro_try(Path::new("/etc/localtime"), Path::new("/etc/localtime"))
            .dev_minimal()
            .tmpfs(Path::new("/tmp"))
            .tmpfs(Path::new("/var/tmp"))
    }

    /// Add CA certificate bind mounts for system-wide trust.
    pub fn ca_certificate_mounts(self, ca_bundle_path: &Path) -> Self {
        self
            .bind_ro(ca_bundle_path, Path::new(SANDBOX_CA_BUNDLE_PATH))
            .bind_ro(ca_bundle_path, Path::new("/etc/pki/tls/certs/ca-bundle.crt"))
            .bind_ro(ca_bundle_path, Path::new("/etc/ssl/cert.pem"))
    }

    /// Add user config directories (read-only).
    pub fn user_config_mounts(self, home: &Path) -> Self {
        let config_dir = home.join(".config");
        self.bind_ro_try(&config_dir, &config_dir)
            .bind_ro_try(&home.join(".gitconfig"), &home.join(".gitconfig"))
            .bind_ro_try(&home.join(".npmrc"), &home.join(".npmrc"))
            .bind_ro_try(&home.join(".cargo"), &home.join(".cargo"))
    }

    /// Set the command to execute inside the sandbox.
    pub fn command(mut self, cmd: &Path, args: &[String]) -> Self {
        self.args.push("--".into());
        self.args.push(cmd.as_os_str().to_owned());
        for arg in args {
            self.args.push(arg.into());
        }
        self
    }

    /// Build the final Command.
    pub fn build(self) -> Command {
        let mut cmd = Command::new("bwrap");
        for arg in &self.args {
            cmd.arg(arg);
        }
        cmd
    }

    /// Get the command line as a string.
    pub fn to_command_line(&self) -> String {
        let mut parts = vec!["bwrap".to_string()];
        for arg in &self.args {
            let s = arg.to_string_lossy();
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
