//! Command-line interface definitions for secure-llm.
//!
//! Uses clap's derive API for type-safe argument parsing.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Security sandbox wrapper for agentic IDEs.
///
/// secure-llm wraps AI coding assistants (Claude Code, Cursor, Windsurf) in a security
/// sandbox that controls filesystem and network access, routes LLM traffic through a
/// corporate gateway, and provides just-in-time permission prompts.
#[derive(Parser, Debug)]
#[command(name = "secure-llm")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Subcommand to run (or omit for normal sandbox mode).
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Tool to launch (claude, cursor, windsurf, or path to binary).
    ///
    /// For built-in profiles (claude, cursor, windsurf), the corresponding
    /// embedded configuration will be used. For custom tools, provide the
    /// full path or use --profile to specify a custom profile.
    ///
    /// Required unless using a subcommand like `internal-shim`.
    pub tool: Option<String>,

    /// Arguments to pass to the tool.
    ///
    /// All arguments after the tool name are passed through to the wrapped
    /// tool without modification.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub tool_args: Vec<String>,

    /// Pre-map port from sandbox to host (repeatable).
    ///
    /// Format: HOST_PORT:CONTAINER_PORT (e.g., -p 3000:3000)
    /// These ports will be bridged automatically without prompting.
    #[arg(short = 'p', long = "publish", value_name = "HOST:CONTAINER")]
    pub publish: Vec<String>,

    /// Pre-allow domain for this session (repeatable).
    ///
    /// These domains will be allowed without prompting for the duration
    /// of this session. They are not persisted to the allowlist.
    #[arg(short = 'd', long = "allow-domain", value_name = "DOMAIN")]
    pub allow_domains: Vec<String>,

    /// Path to additional config file.
    ///
    /// This config file is merged on top of system and user configs,
    /// giving it the highest priority (except for CLI flags).
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Use specific tool profile.
    ///
    /// Override automatic profile detection based on tool name.
    /// Can be a built-in profile name or path to a custom profile.
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// Run without TUI (fail closed, log only).
    ///
    /// In headless mode, all permission prompts will automatically fail
    /// closed (deny). Useful for CI/automated environments where interactive
    /// prompts are not possible.
    #[arg(long = "headless")]
    pub headless: bool,

    /// Increase log verbosity.
    ///
    /// Can be specified multiple times:
    /// -v    = info level
    /// -vv   = debug level
    /// -vvv  = trace level
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// Subcommands for secure-llm.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Internal shim for TCP-to-Unix socket forwarding (hidden).
    ///
    /// This command runs inside the sandbox to bridge TCP connections
    /// to the host proxy via a Unix socket. It should not be invoked
    /// directly by users.
    #[command(name = "internal-shim", hide = true)]
    InternalShim {
        /// Path to the Unix socket to forward to.
        #[arg(required = true)]
        socket_path: PathBuf,
    },

    /// Internal TUI subprocess (hidden).
    ///
    /// This command runs the TUI in a separate process, communicating
    /// with the main proxy process via Unix socket IPC. It is spawned
    /// automatically by the main process in a tmux sidecar pane.
    #[command(name = "internal-tui", hide = true)]
    InternalTui {
        /// Path to the Unix socket for IPC with the main process.
        #[arg(long = "socket-path", required = true)]
        socket_path: PathBuf,
    },
}

impl Cli {
    /// Parse port mapping string into (host_port, container_port) tuple.
    ///
    /// Returns None if the format is invalid.
    pub fn parse_port_mapping(mapping: &str) -> Option<(u16, u16)> {
        let parts: Vec<&str> = mapping.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let host_port: u16 = parts[0].parse().ok()?;
        let container_port: u16 = parts[1].parse().ok()?;

        Some((host_port, container_port))
    }

    /// Get all parsed port mappings.
    ///
    /// Returns a Vec of (host_port, container_port) tuples.
    /// Invalid mappings are silently skipped.
    pub fn port_mappings(&self) -> Vec<(u16, u16)> {
        self.publish
            .iter()
            .filter_map(|m| Self::parse_port_mapping(m))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_mapping_valid() {
        assert_eq!(Cli::parse_port_mapping("3000:3000"), Some((3000, 3000)));
        assert_eq!(Cli::parse_port_mapping("8080:80"), Some((8080, 80)));
        assert_eq!(Cli::parse_port_mapping("443:8443"), Some((443, 8443)));
    }

    #[test]
    fn test_parse_port_mapping_invalid() {
        assert_eq!(Cli::parse_port_mapping("invalid"), None);
        assert_eq!(Cli::parse_port_mapping("3000"), None);
        assert_eq!(Cli::parse_port_mapping("3000:"), None);
        assert_eq!(Cli::parse_port_mapping(":3000"), None);
        assert_eq!(Cli::parse_port_mapping("abc:def"), None);
        assert_eq!(Cli::parse_port_mapping("3000:3000:3000"), None);
    }

    #[test]
    fn test_cli_parse_basic() {
        let cli = Cli::parse_from(["secure-llm", "claude"]);
        assert_eq!(cli.tool, Some("claude".to_string()));
        assert!(cli.tool_args.is_empty());
        assert!(!cli.headless);
        assert_eq!(cli.verbose, 0);
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_parse_with_args() {
        // Note: Using "--foo" instead of "--help" because clap intercepts --help
        // In production, tool args like "--help" would need to come after "--"
        let cli = Cli::parse_from(["secure-llm", "claude", "--foo", "extra"]);
        assert_eq!(cli.tool, Some("claude".to_string()));
        assert_eq!(cli.tool_args, vec!["--foo", "extra"]);
    }

    #[test]
    fn test_cli_parse_with_options() {
        let cli = Cli::parse_from([
            "secure-llm",
            "-p",
            "3000:3000",
            "-p",
            "8080:80",
            "-d",
            "api.example.com",
            "--headless",
            "-vv",
            "cursor",
            "--",
            "arg1",
        ]);

        assert_eq!(cli.tool, Some("cursor".to_string()));
        assert_eq!(cli.publish, vec!["3000:3000", "8080:80"]);
        assert_eq!(cli.allow_domains, vec!["api.example.com"]);
        assert!(cli.headless);
        assert_eq!(cli.verbose, 2);
        assert_eq!(cli.tool_args, vec!["arg1"]);
    }

    #[test]
    fn test_port_mappings() {
        let cli = Cli::parse_from([
            "secure-llm",
            "-p",
            "3000:3000",
            "-p",
            "invalid",
            "-p",
            "8080:80",
            "claude",
        ]);

        let mappings = cli.port_mappings();
        assert_eq!(mappings, vec![(3000, 3000), (8080, 80)]);
    }

    #[test]
    fn test_internal_shim_command() {
        let cli = Cli::parse_from(["secure-llm", "internal-shim", "/tmp/proxy.sock"]);

        assert!(cli.tool.is_none());
        match cli.command {
            Some(Commands::InternalShim { socket_path }) => {
                assert_eq!(socket_path, PathBuf::from("/tmp/proxy.sock"));
            }
            _ => panic!("Expected InternalShim command"),
        }
    }

    #[test]
    fn test_internal_tui_command() {
        let cli = Cli::parse_from([
            "secure-llm",
            "internal-tui",
            "--socket-path",
            "/tmp/tui.sock",
        ]);

        assert!(cli.tool.is_none());
        match cli.command {
            Some(Commands::InternalTui { socket_path }) => {
                assert_eq!(socket_path, PathBuf::from("/tmp/tui.sock"));
            }
            _ => panic!("Expected InternalTui command"),
        }
    }
}
