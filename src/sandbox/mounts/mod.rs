//! Mount source verification for filesystem protection.

pub mod pattern;
pub mod table;

pub use pattern::MountPattern;
pub use table::{MountInfo, MountTable};

use super::error::MountError;
use std::path::{Path, PathBuf};
use tracing::{debug, trace, warn};

const DEFAULT_DENYLIST: &[&str] = &["/etc/shadow", "/etc/gshadow"];

/// Filesystem access verifier.
pub struct MountVerifier {
    mount_table: MountTable,
    denylist: Vec<MountPattern>,
}

impl MountVerifier {
    /// Create a new verifier with a denylist from configuration.
    pub fn new(denylist: &[String]) -> Result<Self, MountError> {
        let mount_table = MountTable::load()?;
        
        let mut patterns = Vec::new();
        for p in DEFAULT_DENYLIST {
            patterns.push(MountPattern::parse(p)?);
        }
        for p in denylist {
            patterns.push(MountPattern::parse(p)?);
        }

        debug!(
            "MountVerifier initialized with {} mounts, {} deny patterns",
            mount_table.mounts.len(),
            patterns.len()
        );

        Ok(Self {
            mount_table,
            denylist: patterns,
        })
    }

    /// Create a verifier with a custom mount table (for testing).
    #[cfg(test)]
    pub fn with_mount_table(
        mount_table: MountTable,
        denylist: &[String],
    ) -> Result<Self, MountError> {
        let denylist: Result<Vec<MountPattern>, MountError> =
            denylist.iter().map(|p| MountPattern::parse(p)).collect();
        Ok(Self {
            mount_table,
            denylist: denylist?,
        })
    }

    /// Check if a path is allowed (not on a denied mount source and not in denylist).
    #[must_use = "verification result must be checked"]
    pub fn verify_path(&self, path: &Path) -> Result<PathBuf, MountError> {
        trace!("Verifying path: {:?}", path);

        let absolute_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| MountError::PathResolution {
                    path: path.to_path_buf(),
                    source: e,
                })?
                .join(path)
        };

        // Check if the requested path (normalized) is denied, even if it doesn't exist.
        let normalized_path = self.normalize_path(&absolute_path);
        if self.is_path_denied(&normalized_path) {
             warn!("Access denied: path {:?} is in denylist", path);
             return Err(MountError::DeniedPath {
                 path: path.to_path_buf(),
             });
        }

        let mut current = absolute_path;
        while !current.exists() {
            match current.parent() {
                Some(p) if !p.as_os_str().is_empty() => {
                    current = p.to_path_buf();
                }
                _ => {
                    return Err(MountError::NoMountFound {
                        path: path.to_path_buf(),
                    });
                }
            }
        }

        let canonical_ancestor =
            std::fs::canonicalize(&current).map_err(|e| MountError::PathResolution {
                path: current.clone(),
                source: e,
            })?;

        // Double check canonical path (in case of symlinks into denied areas)
        if self.is_path_denied(&canonical_ancestor) {
             warn!("Access denied: path {:?} resolves to denied path {:?}", path, canonical_ancestor);
             return Err(MountError::DeniedPath {
                 path: path.to_path_buf(),
             });
        }

        let mount = self
            .mount_table
            .find_mount(&canonical_ancestor)
            .ok_or_else(|| MountError::NoMountFound {
                path: path.to_path_buf(),
            })?;

        if self.is_denied(&mount.source) {
            warn!(
                "Access denied: path {:?} resolves to denied mount source {}",
                path, mount.source
            );
            return Err(MountError::DeniedMountSource {
                path: path.to_path_buf(),
                mount_source: mount.source.clone(),
            });
        }

        Ok(canonical_ancestor)
    }

    /// Check multiple paths, returning first error or all canonical paths.
    pub fn verify_paths(&self, paths: &[PathBuf]) -> Result<Vec<PathBuf>, MountError> {
        paths.iter().map(|p| self.verify_path(p)).collect()
    }

    fn normalize_path(&self, path: &Path) -> PathBuf {
        let components = path.components();
        let mut stack = Vec::new();
        for component in components {
            match component {
                std::path::Component::CurDir => {},
                std::path::Component::ParentDir => { stack.pop(); },
                c => stack.push(c),
            }
        }
        stack.iter().collect()
    }

    fn is_denied(&self, source: &str) -> bool {
        self.denylist.iter().any(|pattern| pattern.matches(source))
    }

    fn is_path_denied(&self, path: &Path) -> bool {
        self.denylist.iter().any(|pattern| {
            match pattern {
                MountPattern::Exact(p) => path.starts_with(p),
                MountPattern::Prefix(p) => path.to_string_lossy().starts_with(p),
                _ => false,
            }
        })
    }

    /// Get a reference to the mount table (for debugging/inspection).
    pub fn mount_table(&self) -> &MountTable {
        &self.mount_table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MOUNTINFO: &str = r#"
22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
24 22 0:22 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
28 22 0:25 / /home rw,relatime - ext4 /dev/sda2 rw
35 28 0:30 / /home/user/sensitive rw,relatime - nfs 10.1.2.3:/exports rw,vers=4
40 22 0:35 / /mnt/data rw,relatime - ext4 UUID=abc123-def456 rw
"#;

    #[test]
    fn test_parse_mountinfo() {
        let table = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        assert!(!table.mounts.is_empty());
        let sources: Vec<&str> = table.mounts.iter().map(|m| m.source.as_str()).collect();
        assert!(sources.contains(&"/dev/sda1"));
        assert!(sources.contains(&"10.1.2.3:/exports"));
    }

    #[test]
    fn test_most_specific_mount() {
        let table = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        let mount = table.find_mount(Path::new("/home/user/sensitive/data")).unwrap();
        assert_eq!(mount.source, "10.1.2.3:/exports");
    }

    #[test]
    fn test_mount_pattern() {
        let pattern = MountPattern::parse("10.1.2.3:*").unwrap();
        assert!(pattern.matches("10.1.2.3:/exports"));
    }

    #[test]
    fn test_denylist_matching() {
        let table = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        let verifier = MountVerifier::with_mount_table(table, &["10.1.2.3:/exports".to_string()]).unwrap();
        assert!(verifier.is_denied("10.1.2.3:/exports"));
    }
}