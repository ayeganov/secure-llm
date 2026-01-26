//! Handle to a running sandbox.

use std::path::PathBuf;
use std::process::{Child, ExitStatus};
use super::error::BwrapError;

/// Handle to a running sandbox.
pub struct SandboxHandle {
    pub(crate) child: Child,
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
