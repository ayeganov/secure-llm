//! Pattern matching for mount sources.

use super::super::error::MountError;

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
    pub fn parse(pattern: &str) -> Result<Self, MountError> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return Err(MountError::InvalidPattern("Empty pattern".to_string()));
        }

        if pattern.starts_with("UUID=") {
            Ok(MountPattern::Uuid(pattern.to_string()))
        } else if let Some(prefix) = pattern.strip_suffix('*') {
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