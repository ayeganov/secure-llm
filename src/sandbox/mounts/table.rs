//! Parsed mount table from /proc/self/mountinfo.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use super::super::error::MountError;

/// Information about a mounted filesystem.
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
#[derive(Debug)]
pub struct MountTable {
    pub(crate) mounts: Vec<MountInfo>,
    #[allow(dead_code)]
    by_mount_point: HashMap<PathBuf, usize>,
}

impl MountTable {
    /// Load and parse /proc/self/mountinfo.
    pub fn load() -> Result<Self, MountError> {
        let content = fs::read_to_string("/proc/self/mountinfo")
            .map_err(MountError::MountInfoRead)?;
        Self::parse(&content)
    }

    /// Parse mount table from a string.
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

        mounts.sort_by(|a, b| {
            let a_depth = a.mount_point.components().count();
            let b_depth = b.mount_point.components().count();
            b_depth.cmp(&a_depth)
        });

        by_mount_point.clear();
        for (idx, mount) in mounts.iter().enumerate() {
            by_mount_point.insert(mount.mount_point.clone(), idx);
        }

        Ok(Self {
            mounts,
            by_mount_point,
        })
    }

    pub(crate) fn parse_line(line: &str, line_num: usize) -> Result<MountInfo, MountError> {
        let parts: Vec<&str> = line.splitn(2, " - ").collect();
        if parts.len() != 2 {
            return Err(MountError::MountInfoParse {
                line_num,
                message: "Missing ' - ' separator".to_string(),
            });
        }

        let before_sep: Vec<&str> = parts[0].split_whitespace().collect();
        let after_sep: Vec<&str> = parts[1].split_whitespace().collect();

        if before_sep.len() < 6 {
            return Err(MountError::MountInfoParse {
                line_num,
                message: format!("Expected at least 6 fields before separator, got {}", before_sep.len()),
            });
        }

        if after_sep.len() < 2 {
            return Err(MountError::MountInfoParse {
                line_num,
                message: format!("Expected at least 2 fields after separator, got {}", after_sep.len()),
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
    pub fn find_mount(&self, path: &Path) -> Option<&MountInfo> {
        self.mounts
            .iter()
            .find(|mount| path.starts_with(&mount.mount_point))
    }

    /// Get the mount source for a path.
    pub fn get_source(&self, path: &Path) -> Option<&str> {
        self.find_mount(path).map(|m| m.source.as_str())
    }

    /// Get all mounts.
    pub fn mounts(&self) -> &[MountInfo] {
        &self.mounts
    }
}

fn unescape_mountinfo(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
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
            if octal.len() == 3 && let Ok(byte) = u8::from_str_radix(&octal, 8) {
                result.push(byte as char);
                continue;
            }
            result.push('\\');
            result.push_str(&octal);
        } else {
            result.push(c);
        }
    }
    result
}