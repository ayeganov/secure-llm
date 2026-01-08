//! Mount source verification for filesystem protection.
//!
//! This module prevents access to sensitive mount sources (NFS exports, specific
//! block devices) regardless of path traversal or symlink attacks.
//!
//! # Security Model
//!
//! The verification flow:
//! 1. Resolve all symlinks to get the canonical path
//! 2. Handle non-existent paths by walking up to an existing ancestor
//! 3. Find the most specific mount point containing the path
//! 4. Compare mount source against the configured denylist
//! 5. Log and deny access to sensitive mount sources
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::sandbox::mounts::{MountTable, MountVerifier};
//!
//! let verifier = MountVerifier::new(&["10.1.2.3:/secure-exports".to_string()])?;
//!
//! // This will succeed if the path is not on a denied mount
//! let canonical = verifier.verify_path(Path::new("/home/user/project"))?;
//!
//! // This will fail if /mnt/secure is on the denylist
//! let result = verifier.verify_path(Path::new("/mnt/secure/data"));
//! assert!(result.is_err());
//! ```

use super::error::MountError;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, trace, warn};

/// Information about a mounted filesystem.
///
/// Parsed from `/proc/self/mountinfo` format:
/// ```text
/// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext4 /dev/sda1 rw,errors=remount-ro
/// ```
#[derive(Debug, Clone)]
pub struct MountInfo {
    /// Mount ID from mountinfo.
    pub mount_id: u32,
    /// Parent mount ID.
    pub parent_id: u32,
    /// Device major:minor string.
    pub device: String,
    /// Root of the mount within the filesystem.
    pub root: PathBuf,
    /// Mount point (where it's visible in the namespace).
    pub mount_point: PathBuf,
    /// Mount options (before the separator).
    pub options: Vec<String>,
    /// Filesystem type (ext4, nfs, tmpfs, etc.).
    pub fs_type: String,
    /// Mount source (device path, NFS export, etc.).
    pub source: String,
    /// Super options (after the separator).
    pub super_options: Vec<String>,
}

/// Parsed mount table from /proc/self/mountinfo.
///
/// Provides efficient lookup of mount information for any path.
#[derive(Debug)]
pub struct MountTable {
    /// All mount entries, ordered by mount point depth (deepest first for efficient lookup).
    mounts: Vec<MountInfo>,
    /// Index by mount point for direct lookups.
    #[allow(dead_code)]
    by_mount_point: HashMap<PathBuf, usize>,
}

impl MountTable {
    /// Load and parse /proc/self/mountinfo.
    ///
    /// # Errors
    ///
    /// Returns `MountError::MountInfoRead` if the file cannot be read,
    /// or `MountError::MountInfoParse` if parsing fails.
    pub fn load() -> Result<Self, MountError> {
        let content = fs::read_to_string("/proc/self/mountinfo")
            .map_err(MountError::MountInfoRead)?;
        Self::parse(&content)
    }

    /// Parse mount table from a string (for testing).
    ///
    /// # Errors
    ///
    /// Returns `MountError::MountInfoParse` if parsing fails.
    pub fn parse(content: &str) -> Result<Self, MountError> {
        let mut mounts = Vec::new();
        let mut by_mount_point = HashMap::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let mount = Self::parse_line(line, line_idx + 1)?;
            by_mount_point.insert(mount.mount_point.clone(), mounts.len());
            mounts.push(mount);
        }

        // Sort by mount point depth (component count), deepest first.
        // This ensures find_mount returns the most specific mount.
        mounts.sort_by(|a, b| {
            let a_depth = a.mount_point.components().count();
            let b_depth = b.mount_point.components().count();
            b_depth.cmp(&a_depth) // Descending order
        });

        // Rebuild index after sorting
        by_mount_point.clear();
        for (idx, mount) in mounts.iter().enumerate() {
            by_mount_point.insert(mount.mount_point.clone(), idx);
        }

        Ok(Self {
            mounts,
            by_mount_point,
        })
    }

    /// Parse a single line from mountinfo.
    ///
    /// Format: mount_id parent_id major:minor root mount_point options optional_fields - fs_type source super_options
    fn parse_line(line: &str, line_num: usize) -> Result<MountInfo, MountError> {
        // Split by " - " to separate the optional fields from fs_type/source/super_options
        let parts: Vec<&str> = line.splitn(2, " - ").collect();
        if parts.len() != 2 {
            return Err(MountError::MountInfoParse {
                line_num,
                message: "Missing ' - ' separator".to_string(),
            });
        }

        let before_sep: Vec<&str> = parts[0].split_whitespace().collect();
        let after_sep: Vec<&str> = parts[1].split_whitespace().collect();

        // Before separator: mount_id parent_id device root mount_point options [optional_fields...]
        if before_sep.len() < 6 {
            return Err(MountError::MountInfoParse {
                line_num,
                message: format!(
                    "Expected at least 6 fields before separator, got {}",
                    before_sep.len()
                ),
            });
        }

        // After separator: fs_type source [super_options...]
        if after_sep.len() < 2 {
            return Err(MountError::MountInfoParse {
                line_num,
                message: format!(
                    "Expected at least 2 fields after separator, got {}",
                    after_sep.len()
                ),
            });
        }

        let mount_id: u32 = before_sep[0].parse().map_err(|_| MountError::MountInfoParse {
            line_num,
            message: format!("Invalid mount_id: {}", before_sep[0]),
        })?;

        let parent_id: u32 = before_sep[1].parse().map_err(|_| MountError::MountInfoParse {
            line_num,
            message: format!("Invalid parent_id: {}", before_sep[1]),
        })?;

        let device = before_sep[2].to_string();
        let root = PathBuf::from(unescape_mountinfo(before_sep[3]));
        let mount_point = PathBuf::from(unescape_mountinfo(before_sep[4]));
        let options: Vec<String> = before_sep[5].split(',').map(String::from).collect();

        let fs_type = after_sep[0].to_string();
        let source = unescape_mountinfo(after_sep[1]);
        let super_options: Vec<String> = if after_sep.len() > 2 {
            after_sep[2].split(',').map(String::from).collect()
        } else {
            Vec::new()
        };

        Ok(MountInfo {
            mount_id,
            parent_id,
            device,
            root,
            mount_point,
            options,
            fs_type,
            source,
            super_options,
        })
    }

    /// Find the mount that contains a given path.
    ///
    /// Returns the most specific (deepest nested) mount point that is
    /// a prefix of the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to look up. Should be canonical (no symlinks).
    pub fn find_mount(&self, path: &Path) -> Option<&MountInfo> {
        // Mounts are sorted by depth (deepest first), so first match is most specific
        self.mounts
            .iter()
            .find(|mount| path.starts_with(&mount.mount_point))
    }

    /// Get the mount source for a path.
    ///
    /// Convenience method that returns just the source string.
    pub fn get_source(&self, path: &Path) -> Option<&str> {
        self.find_mount(path).map(|m| m.source.as_str())
    }

    /// Get all mounts (for debugging/inspection).
    pub fn mounts(&self) -> &[MountInfo] {
        &self.mounts
    }
}

/// Pattern for matching mount sources in the denylist.
#[derive(Debug, Clone)]
pub enum MountPattern {
    /// Exact match: "10.1.2.3:/secure-exports"
    Exact(String),
    /// UUID match: "UUID=abc123..."
    Uuid(String),
    /// Prefix match: "10.1.2.3:*" (all exports from a host)
    Prefix(String),
}

impl MountPattern {
    /// Parse a denylist pattern string into a MountPattern.
    ///
    /// Patterns:
    /// - `10.1.2.3:*` -> Prefix match (all exports from host)
    /// - `UUID=abc123...` -> UUID match
    /// - `10.1.2.3:/export` -> Exact match
    pub fn parse(pattern: &str) -> Result<Self, MountError> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return Err(MountError::InvalidPattern("Empty pattern".to_string()));
        }

        if pattern.starts_with("UUID=") {
            Ok(MountPattern::Uuid(pattern.to_string()))
        } else if pattern.ends_with(":*") {
            // Prefix match: "host:*" matches "host:/any/export"
            let prefix = pattern.strip_suffix('*').unwrap();
            Ok(MountPattern::Prefix(prefix.to_string()))
        } else {
            Ok(MountPattern::Exact(pattern.to_string()))
        }
    }

    /// Check if a mount source matches this pattern.
    pub fn matches(&self, source: &str) -> bool {
        match self {
            MountPattern::Exact(pattern) => source == pattern,
            MountPattern::Uuid(pattern) => source == pattern,
            MountPattern::Prefix(prefix) => source.starts_with(prefix),
        }
    }
}

/// Filesystem access verifier.
///
/// Verifies that paths don't resolve to sensitive mount sources
/// before allowing bind mounts or other access.
pub struct MountVerifier {
    mount_table: MountTable,
    denylist: Vec<MountPattern>,
}

impl MountVerifier {
    /// Create a new verifier with a denylist from configuration.
    ///
    /// # Arguments
    ///
    /// * `denylist` - List of mount source patterns to deny.
    ///
    /// # Errors
    ///
    /// Returns error if mount table cannot be loaded or patterns are invalid.
    pub fn new(denylist: &[String]) -> Result<Self, MountError> {
        let mount_table = MountTable::load()?;
        let denylist: Result<Vec<MountPattern>, MountError> =
            denylist.iter().map(|p| MountPattern::parse(p)).collect();
        let denylist = denylist?;

        debug!(
            "MountVerifier initialized with {} mounts, {} deny patterns",
            mount_table.mounts.len(),
            denylist.len()
        );

        Ok(Self {
            mount_table,
            denylist,
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

    /// Check if a path is allowed (not on a denied mount source).
    ///
    /// This handles non-existent paths by verifying the nearest existing ancestor.
    /// This is critical for the common case of `secure-llm cursor new_project`
    /// where `new_project` doesn't exist yet.
    ///
    /// # Returns
    ///
    /// - `Ok(canonical_path)` if the path is allowed
    /// - `Err(MountError::DeniedMountSource)` if the path is on a denied mount
    /// - `Err(MountError::PathResolution)` if the path cannot be resolved
    ///
    /// # Security
    ///
    /// This function:
    /// 1. Forces the path to be absolute (preventing relative path tricks)
    /// 2. Walks up to find an existing ancestor (handles new directories)
    /// 3. Canonicalizes to resolve symlinks (prevents symlink attacks)
    /// 4. Checks the mount source against the denylist
    #[must_use = "verification result must be checked"]
    pub fn verify_path(&self, path: &Path) -> Result<PathBuf, MountError> {
        trace!("Verifying path: {:?}", path);

        // Step 0: Force absolute path before traversal.
        // This ensures we always walk up to "/" which definitely exists,
        // avoiding brittle behavior with relative paths like "foo/bar"
        // where parent() eventually returns "".
        let mut current = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| MountError::PathResolution {
                    path: path.to_path_buf(),
                    source: e,
                })?
                .join(path)
        };

        trace!("Absolute path: {:?}", current);

        // Step 1: Walk up until we find a path that exists.
        // This handles the "new_project" case where the directory doesn't exist yet.
        while !current.exists() {
            trace!("Path {:?} does not exist, checking parent", current);
            match current.parent() {
                Some(p) if !p.as_os_str().is_empty() => {
                    current = p.to_path_buf();
                }
                _ => {
                    // We've reached the root or an empty path without finding anything
                    return Err(MountError::NoMountFound {
                        path: path.to_path_buf(),
                    });
                }
            }
        }

        trace!("Found existing ancestor: {:?}", current);

        // Step 2: Canonicalize the existing ancestor to resolve symlinks.
        let canonical_ancestor =
            std::fs::canonicalize(&current).map_err(|e| MountError::PathResolution {
                path: current.clone(),
                source: e,
            })?;

        trace!("Canonical ancestor: {:?}", canonical_ancestor);

        // Step 3: Find mount source for this ancestor.
        let mount = self
            .mount_table
            .find_mount(&canonical_ancestor)
            .ok_or_else(|| MountError::NoMountFound {
                path: path.to_path_buf(),
            })?;

        trace!(
            "Mount for {:?}: point={:?}, source={}",
            canonical_ancestor,
            mount.mount_point,
            mount.source
        );

        // Step 4: Check against denylist.
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

        debug!(
            "Path {:?} verified: mount source {} is allowed",
            path, mount.source
        );
        Ok(canonical_ancestor)
    }

    /// Check multiple paths, returning first error or all canonical paths.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<PathBuf>)` with all canonical paths if all are allowed
    /// - `Err` with the first error encountered
    pub fn verify_paths(&self, paths: &[PathBuf]) -> Result<Vec<PathBuf>, MountError> {
        paths.iter().map(|p| self.verify_path(p)).collect()
    }

    /// Check if a mount source is in the denylist.
    fn is_denied(&self, source: &str) -> bool {
        self.denylist.iter().any(|pattern| pattern.matches(source))
    }

    /// Get a reference to the mount table (for debugging/inspection).
    pub fn mount_table(&self) -> &MountTable {
        &self.mount_table
    }
}

/// Unescape special characters in mountinfo fields.
///
/// Mountinfo escapes spaces as \040, newlines as \012, etc.
fn unescape_mountinfo(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            // Try to read 3 octal digits
            let mut octal = String::new();
            for _ in 0..3 {
                if let Some(&d) = chars.peek() {
                    if d.is_ascii_digit() && d < '8' {
                        octal.push(d);
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            if octal.len() == 3
                && let Ok(byte) = u8::from_str_radix(&octal, 8)
            {
                result.push(byte as char);
                continue;
            }
            // Not a valid escape, keep the backslash and whatever we read
            result.push('\\');
            result.push_str(&octal);
        } else {
            result.push(c);
        }
    }

    result
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

        // Check that we parsed the expected mounts
        let sources: Vec<&str> = table.mounts.iter().map(|m| m.source.as_str()).collect();
        assert!(sources.contains(&"/dev/sda1"));
        assert!(sources.contains(&"/dev/sda2"));
        assert!(sources.contains(&"10.1.2.3:/exports"));
    }

    #[test]
    fn test_most_specific_mount() {
        let table = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();

        // /home/user/sensitive/data should find the NFS mount, not /home
        let mount = table
            .find_mount(Path::new("/home/user/sensitive/data"))
            .unwrap();
        assert_eq!(mount.source, "10.1.2.3:/exports");

        // /home/user/other should find /home mount
        let mount = table.find_mount(Path::new("/home/user/other")).unwrap();
        assert_eq!(mount.source, "/dev/sda2");

        // / should find the root mount
        let mount = table.find_mount(Path::new("/")).unwrap();
        assert_eq!(mount.source, "/dev/sda1");
    }

    #[test]
    fn test_mount_pattern_exact() {
        let pattern = MountPattern::parse("10.1.2.3:/exports").unwrap();
        assert!(pattern.matches("10.1.2.3:/exports"));
        assert!(!pattern.matches("10.1.2.3:/other"));
        assert!(!pattern.matches("10.1.2.4:/exports"));
    }

    #[test]
    fn test_mount_pattern_prefix() {
        let pattern = MountPattern::parse("10.1.2.3:*").unwrap();
        assert!(pattern.matches("10.1.2.3:/exports"));
        assert!(pattern.matches("10.1.2.3:/other/path"));
        assert!(!pattern.matches("10.1.2.4:/exports"));
    }

    #[test]
    fn test_mount_pattern_uuid() {
        let pattern = MountPattern::parse("UUID=abc123-def456").unwrap();
        assert!(pattern.matches("UUID=abc123-def456"));
        assert!(!pattern.matches("UUID=other-uuid"));
        assert!(!pattern.matches("/dev/sda1"));
    }

    #[test]
    fn test_mount_pattern_invalid() {
        let result = MountPattern::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn test_unescape_mountinfo() {
        // Space is \040 in octal
        assert_eq!(unescape_mountinfo(r"/path\040with\040spaces"), "/path with spaces");

        // Newline is \012
        assert_eq!(unescape_mountinfo(r"line1\012line2"), "line1\nline2");

        // No escapes
        assert_eq!(unescape_mountinfo("/normal/path"), "/normal/path");

        // Invalid escape (not 3 digits)
        assert_eq!(unescape_mountinfo(r"/path\04x"), "/path\\04x");
    }

    #[test]
    fn test_denylist_matching() {
        let table = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        let verifier = MountVerifier::with_mount_table(
            table,
            &["10.1.2.3:/exports".to_string()],
        )
        .unwrap();

        assert!(verifier.is_denied("10.1.2.3:/exports"));
        assert!(!verifier.is_denied("/dev/sda1"));
        assert!(!verifier.is_denied("10.1.2.4:/exports"));
    }

    #[test]
    fn test_denylist_prefix_matching() {
        let table = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        let verifier = MountVerifier::with_mount_table(
            table,
            &["10.1.2.3:*".to_string()],
        )
        .unwrap();

        assert!(verifier.is_denied("10.1.2.3:/exports"));
        assert!(verifier.is_denied("10.1.2.3:/any/path"));
        assert!(!verifier.is_denied("10.1.2.4:/exports"));
    }

    #[test]
    fn test_parse_mountinfo_with_optional_fields() {
        // Some mounts have optional fields like "master:N" or "shared:N"
        let mountinfo = r#"
22 1 8:1 / / rw,relatime shared:1 master:2 - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw,nosuid - proc proc rw
"#;
        let table = MountTable::parse(mountinfo).unwrap();
        assert_eq!(table.mounts.len(), 2);
    }

    #[test]
    fn test_parse_line_error_no_separator() {
        let result = MountTable::parse_line("22 1 8:1 / / rw,relatime ext4 /dev/sda1 rw", 1);
        assert!(matches!(result, Err(MountError::MountInfoParse { .. })));
    }

    #[test]
    fn test_verify_path_with_real_filesystem() {
        // This test uses the real filesystem
        // Skip if denylist can't be loaded
        let verifier = match MountVerifier::new(&[]) {
            Ok(v) => v,
            Err(_) => return, // Skip on systems where mountinfo can't be read
        };

        // Current directory should be verifiable
        let cwd = std::env::current_dir().unwrap();
        let result = verifier.verify_path(&cwd);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_nonexistent_path_verifies_ancestor() {
        // Create a temp directory, then verify a non-existent path within it
        let temp_dir = tempfile::tempdir().unwrap();
        let nonexistent = temp_dir.path().join("new_project").join("deep").join("path");

        // Path doesn't exist
        assert!(!nonexistent.exists());
        // But temp_dir does
        assert!(temp_dir.path().exists());

        // Should succeed with empty denylist
        let verifier = match MountVerifier::new(&[]) {
            Ok(v) => v,
            Err(_) => return,
        };

        let result = verifier.verify_path(&nonexistent);
        assert!(result.is_ok());

        // The result should be the canonical path of the existing ancestor
        let canonical = result.unwrap();
        assert!(canonical.exists());
    }

    #[test]
    fn test_get_source() {
        let table = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();

        assert_eq!(table.get_source(Path::new("/")), Some("/dev/sda1"));
        assert_eq!(table.get_source(Path::new("/home")), Some("/dev/sda2"));
        assert_eq!(
            table.get_source(Path::new("/home/user/sensitive")),
            Some("10.1.2.3:/exports")
        );
    }
}
