//! Startup garbage collection for crashed sessions.
//!
//! This module cleans up stale resources (network namespaces, temp directories)
//! from previous secure-llm sessions that were terminated abnormally (SIGKILL,
//! power loss, etc.) where the Drop trait never ran.
//!
//! # The Problem
//!
//! We rely on `Drop` traits to clean up network namespaces and temp directories.
//! But if `secure-llm` is killed via `SIGKILL` (kill -9) or the host loses power,
//! `Drop` never runs. This leaves:
//!
//! - Stale `secure-llm-*` namespaces in `/run/netns/`
//! - Orphaned temp directories in `/tmp/`
//!
//! # The Solution
//!
//! Run garbage collection at startup before creating new resources.
//!
//! # Example
//!
//! ```no_run
//! use secure_llm::sandbox::cleanup::cleanup_stale_resources;
//!
//! // In main(), before creating any sandbox resources
//! cleanup_stale_resources();
//! ```

use std::fs;
use std::path::Path;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Clean up stale resources from previous crashed sessions.
///
/// This function should be called early in `main()` before creating
/// new sandbox resources.
pub fn cleanup_stale_resources() {
    info!("Checking for stale resources from crashed sessions");
    cleanup_stale_namespaces();
    cleanup_stale_temp_dirs();
}

/// Remove network namespaces where the owning PID no longer exists.
fn cleanup_stale_namespaces() {
    let netns_dir = Path::new("/run/netns");
    if !netns_dir.exists() {
        debug!("No /run/netns directory, skipping namespace cleanup");
        return;
    }

    let entries = match fs::read_dir(netns_dir) {
        Ok(e) => e,
        Err(e) => {
            debug!("Cannot read /run/netns: {}", e);
            return;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Our namespaces are named "secure-llm-<pid>"
        if let Some(pid_str) = name_str.strip_prefix("secure-llm-")
            && let Ok(pid) = pid_str.parse::<u32>()
        {
            // Check if PID still exists
            if !process_exists(pid) {
                info!("Cleaning up stale namespace: {}", name_str);
                // Best effort cleanup - ignore errors
                if let Err(e) = delete_namespace(&name_str) {
                    warn!("Failed to delete stale namespace {}: {}", name_str, e);
                }
            } else {
                debug!(
                    "Namespace {} still has running process (PID {})",
                    name_str, pid
                );
            }
        }
    }
}

/// Remove temp directories where the owning PID no longer exists or they're old.
fn cleanup_stale_temp_dirs() {
    for prefix in &["secure-llm-ca-", "secure-llm-netns-"] {
        cleanup_temp_dirs_with_prefix(prefix);
    }
}

/// Clean up temp directories with a specific prefix.
fn cleanup_temp_dirs_with_prefix(prefix: &str) {
    let tmp_dir = std::env::temp_dir();
    let entries = match fs::read_dir(&tmp_dir) {
        Ok(e) => e,
        Err(e) => {
            debug!("Cannot read temp directory: {}", e);
            return;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str.starts_with(prefix) {
            // Check if the directory is old (> 24 hours)
            // This is a safety measure in case we can't determine the owning process
            if let Ok(metadata) = entry.metadata()
                && let Ok(modified) = metadata.modified()
                && let Ok(age) = SystemTime::now().duration_since(modified)
                && age.as_secs() > 86400
            {
                // Older than 24 hours
                info!("Cleaning up stale temp dir (old): {}", name_str);
                if let Err(e) = fs::remove_dir_all(entry.path()) {
                    warn!("Failed to remove stale temp dir {}: {}", name_str, e);
                }
                continue;
            }

            // Try to extract PID from directory name
            // Format is usually: secure-llm-ca-XXXXXX where XXXXXX is random
            // We can't easily determine the owning PID, so we rely on age check
            debug!("Temp dir {} is recent, skipping", name_str);
        }
    }
}

/// Check if a process with the given PID exists.
fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Delete a network namespace by name.
fn delete_namespace(name: &str) -> Result<(), std::io::Error> {
    use std::process::Command;

    let output = Command::new("ip")
        .args(["netns", "delete", name])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "ip netns delete failed: {}",
            stderr
        )));
    }

    Ok(())
}

/// Get a list of all secure-llm related stale resources.
///
/// This is useful for diagnostics and testing.
pub fn list_stale_resources() -> StaleResources {
    let mut resources = StaleResources::default();

    // Check namespaces
    let netns_dir = Path::new("/run/netns");
    if netns_dir.exists()
        && let Ok(entries) = fs::read_dir(netns_dir)
    {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(pid_str) = name.strip_prefix("secure-llm-")
                && let Ok(pid) = pid_str.parse::<u32>()
                && !process_exists(pid)
            {
                resources.namespaces.push(name);
            }
        }
    }

    // Check temp directories
    let tmp_dir = std::env::temp_dir();
    if let Ok(entries) = fs::read_dir(&tmp_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if (name.starts_with("secure-llm-ca-") || name.starts_with("secure-llm-netns-"))
                && let Ok(metadata) = entry.metadata()
                && let Ok(modified) = metadata.modified()
                && let Ok(age) = SystemTime::now().duration_since(modified)
                && age.as_secs() > 86400
            {
                resources.temp_dirs.push(entry.path());
            }
        }
    }

    resources
}

/// Information about stale resources found on the system.
#[derive(Debug, Default)]
pub struct StaleResources {
    /// Stale network namespace names.
    pub namespaces: Vec<String>,
    /// Stale temp directory paths.
    pub temp_dirs: Vec<std::path::PathBuf>,
}

impl StaleResources {
    /// Check if there are any stale resources.
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty() && self.temp_dirs.is_empty()
    }

    /// Get total count of stale resources.
    pub fn count(&self) -> usize {
        self.namespaces.len() + self.temp_dirs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_process_exists() {
        // PID 1 should always exist (init/systemd)
        assert!(process_exists(1));

        // A very high PID unlikely to exist
        assert!(!process_exists(u32::MAX));
    }

    #[test]
    fn test_list_stale_resources() {
        // This just tests that the function doesn't panic
        let resources = list_stale_resources();
        // We don't assert anything specific since we don't know what resources exist
        let _ = resources.is_empty();
        let _ = resources.count();
    }

    #[test]
    fn test_cleanup_stale_resources_doesnt_panic() {
        // This just tests that the function doesn't panic
        // In a real test environment, it might not have permissions to do anything
        cleanup_stale_resources();
    }

    #[test]
    fn test_stale_resources_empty() {
        let resources = StaleResources::default();
        assert!(resources.is_empty());
        assert_eq!(resources.count(), 0);
    }

    #[test]
    fn test_stale_resources_count() {
        let resources = StaleResources {
            namespaces: vec!["ns1".to_string(), "ns2".to_string()],
            temp_dirs: vec![PathBuf::from("/tmp/test")],
        };
        assert!(!resources.is_empty());
        assert_eq!(resources.count(), 3);
    }
}
