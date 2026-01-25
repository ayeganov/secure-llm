//! Domain policy evaluation engine.
//!
//! This module implements the policy engine that evaluates network requests
//! against configured allowlists, blocklists, graylists, and host rewrite rules.
//!
//! # Policy Evaluation Order
//!
//! 1. Check session deny (user already said no this session)
//! 2. Check blocklist (always blocked)
//! 3. Check graylist (always prompt, even if allowlist would match)
//! 4. Check session allow (user already said yes this session)
//! 5. Check CLI allow (from --allow-domain flag)
//! 6. Check allowlist (permitted without prompting)
//! 7. Unknown domain (requires prompt)
//!
//! # Pattern Matching
//!
//! - Exact match: `github.com`
//! - Wildcard match: `*.github.com` matches `api.github.com`, `raw.github.com`
//!   but NOT `github.com` itself
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::proxy::policy::{PolicyEngine, PolicyDecision};
//! use secure_llm::config::NetworkConfig;
//!
//! let config = NetworkConfig::default();
//! let engine = PolicyEngine::from_config(&config, &[]);
//!
//! match engine.evaluate("pypi.org") {
//!     PolicyDecision::Allow { .. } => println!("Allowed"),
//!     PolicyDecision::Block { .. } => println!("Blocked"),
//!     PolicyDecision::Prompt => println!("Needs user decision"),
//! }
//! ```

use crate::config::NetworkConfig;
use crate::telemetry::{AllowReason, BlockReason};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Result of policy evaluation for a domain.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Allow the connection.
    Allow {
        /// Optional host rewrite target.
        rewrite_to: Option<String>,
        /// Reason for allowing (for audit logging).
        reason: AllowReason,
    },
    /// Block the connection.
    Block {
        /// Reason for blocking (for audit logging).
        reason: BlockReason,
    },
    /// Prompt the user for a decision.
    Prompt,
}

/// Policy engine for domain evaluation.
///
/// The engine maintains both static configuration (from config files)
/// and dynamic session state (user decisions during this session).
pub struct PolicyEngine {
    /// Domains in the allowlist (exact matches, lowercase).
    allowlist_exact: HashSet<String>,
    /// Wildcard patterns in the allowlist (e.g., "*.example.com").
    allowlist_wildcards: Vec<String>,
    /// Domains in the blocklist (exact matches, lowercase).
    blocklist_exact: HashSet<String>,
    /// Wildcard patterns in the blocklist.
    blocklist_wildcards: Vec<String>,
    /// Domains in the graylist (always prompt, exact matches, lowercase).
    graylist_exact: HashSet<String>,
    /// Wildcard patterns in the graylist.
    graylist_wildcards: Vec<String>,
    /// Host rewrite rules (original lowercase -> replacement).
    host_rewrites: HashMap<String, String>,
    /// Session-approved domains (approved by user this session).
    session_allow: RwLock<HashSet<String>>,
    /// Session-denied domains (denied by user this session).
    session_deny: RwLock<HashSet<String>>,
    /// CLI-approved domains (from --allow-domain flag, lowercase).
    cli_allow: HashSet<String>,
}

impl PolicyEngine {
    /// Create a policy engine from configuration and CLI flags.
    ///
    /// # Arguments
    ///
    /// * `config` - Network configuration containing allowlist, blocklist, etc.
    /// * `cli_domains` - Domains pre-allowed via CLI `--allow-domain` flags.
    pub fn from_config(config: &NetworkConfig, cli_domains: &[String]) -> Self {
        let (allowlist_exact, allowlist_wildcards) = split_patterns(&config.allowlist);
        let (blocklist_exact, blocklist_wildcards) = split_patterns(&config.blocklist);
        let (graylist_exact, graylist_wildcards) = split_patterns(&config.graylist);

        // Lowercase all host rewrite keys for case-insensitive matching
        let host_rewrites: HashMap<String, String> = config
            .host_rewrite
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        // Lowercase CLI domains for case-insensitive matching
        let cli_allow: HashSet<String> = cli_domains.iter().map(|d| d.to_lowercase()).collect();

        Self {
            allowlist_exact,
            allowlist_wildcards,
            blocklist_exact,
            blocklist_wildcards,
            graylist_exact,
            graylist_wildcards,
            host_rewrites,
            session_allow: RwLock::new(HashSet::new()),
            session_deny: RwLock::new(HashSet::new()),
            cli_allow,
        }
    }

    /// Evaluate policy for a domain.
    ///
    /// Returns the policy decision: Allow, Block, or Prompt.
    /// Domain matching is case-insensitive.
    pub fn evaluate(&self, domain: &str) -> PolicyDecision {
        let domain_lower = domain.to_lowercase();

        // 1. Check session deny (user already said no)
        if self
            .session_deny
            .read()
            .unwrap()
            .contains(&domain_lower)
        {
            return PolicyDecision::Block {
                reason: BlockReason::UserDenied,
            };
        }

        // 2. Check blocklist (always blocked)
        if self.matches_blocklist(&domain_lower) {
            return PolicyDecision::Block {
                reason: BlockReason::Blocklist,
            };
        }

        // 3. Check graylist (always prompt, even if allowlist would match)
        if self.matches_graylist(&domain_lower) {
            // Check if already approved this session
            if self
                .session_allow
                .read()
                .unwrap()
                .contains(&domain_lower)
            {
                return PolicyDecision::Allow {
                    rewrite_to: self.get_rewrite(&domain_lower),
                    reason: AllowReason::SessionAllow,
                };
            }
            return PolicyDecision::Prompt;
        }

        // 4. Check session allow (user already said yes)
        if self
            .session_allow
            .read()
            .unwrap()
            .contains(&domain_lower)
        {
            return PolicyDecision::Allow {
                rewrite_to: self.get_rewrite(&domain_lower),
                reason: AllowReason::SessionAllow,
            };
        }

        // 5. Check CLI allow (from --allow-domain flag)
        if self.cli_allow.contains(&domain_lower) {
            return PolicyDecision::Allow {
                rewrite_to: self.get_rewrite(&domain_lower),
                reason: AllowReason::CliFlag,
            };
        }

        // 6. Check allowlist
        if self.matches_allowlist(&domain_lower) {
            return PolicyDecision::Allow {
                rewrite_to: self.get_rewrite(&domain_lower),
                reason: AllowReason::BaseAllowlist,
            };
        }

        // 7. Unknown domain - needs prompt
        PolicyDecision::Prompt
    }

    /// Record a user's session decision for a domain.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain the user made a decision about.
    /// * `allowed` - true if user allowed, false if user denied.
    pub fn record_decision(&self, domain: &str, allowed: bool) {
        let domain_lower = domain.to_lowercase();
        if allowed {
            self.session_allow.write().unwrap().insert(domain_lower);
        } else {
            self.session_deny.write().unwrap().insert(domain_lower);
        }
    }

    /// Get the rewrite target for a domain, if any.
    ///
    /// Used to redirect LLM provider domains to the corporate gateway.
    pub fn get_rewrite(&self, domain: &str) -> Option<String> {
        self.host_rewrites.get(&domain.to_lowercase()).cloned()
    }

    /// Check if domain matches the blocklist.
    fn matches_blocklist(&self, domain: &str) -> bool {
        self.blocklist_exact.contains(domain)
            || self
                .blocklist_wildcards
                .iter()
                .any(|p| matches_wildcard(p, domain))
    }

    /// Check if domain matches the graylist.
    fn matches_graylist(&self, domain: &str) -> bool {
        self.graylist_exact.contains(domain)
            || self
                .graylist_wildcards
                .iter()
                .any(|p| matches_wildcard(p, domain))
    }

    /// Check if domain matches the allowlist.
    fn matches_allowlist(&self, domain: &str) -> bool {
        self.allowlist_exact.contains(domain)
            || self
                .allowlist_wildcards
                .iter()
                .any(|p| matches_wildcard(p, domain))
    }

    /// Get the number of session-allowed domains.
    pub fn session_allow_count(&self) -> usize {
        self.session_allow.read().unwrap().len()
    }

    /// Get the number of session-denied domains.
    pub fn session_deny_count(&self) -> usize {
        self.session_deny.read().unwrap().len()
    }

    /// Clear session state (for testing or session reset).
    pub fn clear_session(&self) {
        self.session_allow.write().unwrap().clear();
        self.session_deny.write().unwrap().clear();
    }
}

/// Split patterns into exact matches and wildcards.
///
/// Patterns starting with `*.` are treated as wildcards.
/// All patterns are lowercased for case-insensitive matching.
fn split_patterns(patterns: &[String]) -> (HashSet<String>, Vec<String>) {
    let mut exact = HashSet::new();
    let mut wildcards = Vec::new();

    for pattern in patterns {
        let pattern_lower = pattern.to_lowercase();
        if pattern_lower.starts_with("*.") {
            wildcards.push(pattern_lower);
        } else {
            exact.insert(pattern_lower);
        }
    }

    (exact, wildcards)
}

/// Check if a domain matches a wildcard pattern.
///
/// Pattern `*.example.com` matches:
/// - `sub.example.com`
/// - `deep.sub.example.com`
///
/// But NOT:
/// - `example.com` (the base domain itself)
/// - `fakeexample.com` (different domain)
fn matches_wildcard(pattern: &str, domain: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Domain must end with the suffix AND have something before it
        if domain.ends_with(suffix) {
            let prefix_len = domain.len() - suffix.len();
            // Must have at least one character and a dot before the suffix
            prefix_len > 0 && domain.as_bytes().get(prefix_len - 1) == Some(&b'.')
        } else {
            false
        }
    } else {
        // Not a wildcard pattern - shouldn't happen with split_patterns
        pattern == domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_config() -> NetworkConfig {
        NetworkConfig {
            allowlist: vec![
                "allowed.com".to_string(),
                "*.allowed.com".to_string(),
                "pypi.org".to_string(),
            ],
            blocklist: vec!["blocked.com".to_string(), "*.evil.com".to_string()],
            graylist: vec![
                "gray.allowed.com".to_string(),
                "raw.githubusercontent.com".to_string(),
            ],
            host_rewrite: {
                let mut m = HashMap::new();
                m.insert(
                    "api.anthropic.com".to_string(),
                    "gateway.corp/v1/anthropic".to_string(),
                );
                m
            },
        }
    }

    #[test]
    fn test_wildcard_matching_basic() {
        assert!(matches_wildcard("*.example.com", "sub.example.com"));
        assert!(matches_wildcard("*.example.com", "deep.sub.example.com"));
        assert!(!matches_wildcard("*.example.com", "example.com"));
        assert!(!matches_wildcard("*.example.com", "notexample.com"));
        assert!(!matches_wildcard("*.example.com", "fakeexample.com"));
    }

    #[test]
    fn test_wildcard_matching_edge_cases() {
        // Ensure we don't match domains that just happen to end with the suffix
        assert!(!matches_wildcard("*.github.com", "fakegithub.com"));
        assert!(!matches_wildcard("*.github.com", "notgithub.com"));

        // But we should match proper subdomains
        assert!(matches_wildcard("*.github.com", "api.github.com"));
        assert!(matches_wildcard("*.github.com", "raw.github.com"));
        assert!(matches_wildcard(
            "*.github.com",
            "enterprise.api.github.com"
        ));
    }

    #[test]
    fn test_allowed_domain() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        match engine.evaluate("allowed.com") {
            PolicyDecision::Allow { reason, .. } => {
                assert!(matches!(reason, AllowReason::BaseAllowlist));
            }
            _ => panic!("Expected Allow"),
        }
    }

    #[test]
    fn test_allowed_wildcard() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        match engine.evaluate("sub.allowed.com") {
            PolicyDecision::Allow { reason, .. } => {
                assert!(matches!(reason, AllowReason::BaseAllowlist));
            }
            _ => panic!("Expected Allow for wildcard match"),
        }
    }

    #[test]
    fn test_blocked_domain() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        match engine.evaluate("blocked.com") {
            PolicyDecision::Block { reason } => {
                assert!(matches!(reason, BlockReason::Blocklist));
            }
            _ => panic!("Expected Block"),
        }
    }

    #[test]
    fn test_blocked_wildcard() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        match engine.evaluate("sub.evil.com") {
            PolicyDecision::Block { reason } => {
                assert!(matches!(reason, BlockReason::Blocklist));
            }
            _ => panic!("Expected Block for wildcard match"),
        }
    }

    #[test]
    fn test_graylist_prompts() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        // gray.allowed.com is on graylist AND would match *.allowed.com
        // Graylist should take precedence
        match engine.evaluate("gray.allowed.com") {
            PolicyDecision::Prompt => {}
            _ => panic!("Expected Prompt for graylisted domain"),
        }
    }

    #[test]
    fn test_graylist_with_session_allow() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        // First evaluation should prompt
        assert!(matches!(
            engine.evaluate("raw.githubusercontent.com"),
            PolicyDecision::Prompt
        ));

        // User allows
        engine.record_decision("raw.githubusercontent.com", true);

        // Now should allow
        match engine.evaluate("raw.githubusercontent.com") {
            PolicyDecision::Allow { reason, .. } => {
                assert!(matches!(reason, AllowReason::SessionAllow));
            }
            _ => panic!("Expected Allow after session approval"),
        }
    }

    #[test]
    fn test_unknown_domain_prompts() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        match engine.evaluate("unknown-domain.io") {
            PolicyDecision::Prompt => {}
            _ => panic!("Expected Prompt for unknown domain"),
        }
    }

    #[test]
    fn test_session_deny() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        // User denies unknown domain
        engine.record_decision("unknown.io", false);

        match engine.evaluate("unknown.io") {
            PolicyDecision::Block { reason } => {
                assert!(matches!(reason, BlockReason::UserDenied));
            }
            _ => panic!("Expected Block after user denial"),
        }
    }

    #[test]
    fn test_cli_allow() {
        let config = test_config();
        let cli_domains = vec!["cli-allowed.com".to_string()];
        let engine = PolicyEngine::from_config(&config, &cli_domains);

        match engine.evaluate("cli-allowed.com") {
            PolicyDecision::Allow { reason, .. } => {
                assert!(matches!(reason, AllowReason::CliFlag));
            }
            _ => panic!("Expected Allow for CLI-allowed domain"),
        }
    }

    #[test]
    fn test_host_rewrite() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        // api.anthropic.com should have a rewrite
        assert_eq!(
            engine.get_rewrite("api.anthropic.com"),
            Some("gateway.corp/v1/anthropic".to_string())
        );

        // Case insensitive
        assert_eq!(
            engine.get_rewrite("API.ANTHROPIC.COM"),
            Some("gateway.corp/v1/anthropic".to_string())
        );

        // Unknown domain has no rewrite
        assert_eq!(engine.get_rewrite("example.com"), None);
    }

    #[test]
    fn test_case_insensitive_matching() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        // Allowlist should be case-insensitive
        assert!(matches!(
            engine.evaluate("PYPI.ORG"),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            engine.evaluate("PyPi.Org"),
            PolicyDecision::Allow { .. }
        ));

        // Blocklist should be case-insensitive
        assert!(matches!(
            engine.evaluate("BLOCKED.COM"),
            PolicyDecision::Block { .. }
        ));
    }

    #[test]
    fn test_blocklist_priority_over_allowlist() {
        // If a domain is in both blocklist and allowlist, blocklist wins
        let config = NetworkConfig {
            allowlist: vec!["both.com".to_string()],
            blocklist: vec!["both.com".to_string()],
            graylist: vec![],
            host_rewrite: HashMap::new(),
        };
        let engine = PolicyEngine::from_config(&config, &[]);

        match engine.evaluate("both.com") {
            PolicyDecision::Block { reason } => {
                assert!(matches!(reason, BlockReason::Blocklist));
            }
            _ => panic!("Blocklist should take priority over allowlist"),
        }
    }

    #[test]
    fn test_clear_session() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        engine.record_decision("test.com", true);
        assert_eq!(engine.session_allow_count(), 1);

        engine.clear_session();
        assert_eq!(engine.session_allow_count(), 0);
    }

    #[test]
    fn test_session_counts() {
        let config = test_config();
        let engine = PolicyEngine::from_config(&config, &[]);

        engine.record_decision("allowed1.com", true);
        engine.record_decision("allowed2.com", true);
        engine.record_decision("denied1.com", false);

        assert_eq!(engine.session_allow_count(), 2);
        assert_eq!(engine.session_deny_count(), 1);
    }
}
