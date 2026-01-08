//! secure-llm: Security sandbox wrapper for agentic IDEs
//!
//! This is the main entry point for the secure-llm binary. It handles CLI argument
//! parsing, configuration loading, telemetry initialization, and orchestrates the
//! sandbox launch.
//!
//! # I/O Architecture
//!
//! This binary is designed to wrap agentic IDEs (Claude Code, Cursor, etc.) without
//! interfering with their stdin/stdout/stderr:
//!
//! - **Audit logging**: Goes to syslog (not stdout/stderr), so it never interferes
//!   with the wrapped tool
//! - **Debug logging**: Only emitted during initialization phase to stderr. Once the
//!   sandbox launches, stderr is handed to the wrapped tool
//! - **TUI (Phase 4)**: Runs in a separate tmux pane, completely isolated from the
//!   wrapped tool's terminal
//!
//! The tmux layout will be:
//! - Top pane: The wrapped tool with full stdin/stdout/stderr access
//! - Bottom pane: secure-llm sidecar TUI for permission prompts and logs

use anyhow::{Context, Result};
use clap::Parser;
use secure_llm::{
    cli::Cli,
    config::ConfigLoader,
    telemetry::{self, AuditEvent},
};
use tracing::{debug, info};

fn main() -> Result<()> {
    // Parse CLI arguments first (before any other initialization)
    let cli = Cli::parse();

    // Initialize tracing subscriber for debug logging (stderr only during init)
    // This will be completely silent once we launch the sandbox
    init_tracing(cli.verbose)?;

    debug!("Parsed CLI arguments: {:?}", cli);

    // Initialize telemetry (syslog) - this never touches stdout/stderr
    telemetry::init_logger().context("Failed to initialize telemetry")?;

    // Load configuration with hierarchy merging
    let config_loader = ConfigLoader::new();
    let config = config_loader
        .load(&cli)
        .context("Failed to load configuration")?;

    debug!("Loaded configuration: {:?}", config);

    // Load tool profile
    let profile = config_loader
        .load_profile(&cli.tool, cli.profile.as_deref())
        .context("Failed to load tool profile")?;

    info!(
        "Using profile '{}' for tool '{}'",
        profile.tool.display_name, cli.tool
    );

    // Log session start to syslog
    telemetry::audit().log(AuditEvent::SessionStart {
        user: whoami(),
        tool: cli.tool.clone(),
        pid: std::process::id(),
    });

    // Phase 1: We don't have the sandbox yet, so we fail with a clear message
    // This error goes to stderr, which is acceptable during Phase 1 since
    // we haven't launched the sandbox yet

    // Log session end to syslog
    telemetry::audit().log(AuditEvent::SessionEnd {
        user: whoami(),
        tool: cli.tool,
        duration_sec: 0,
    });

    anyhow::bail!("Sandbox not yet implemented. This is expected in Phase 1.")
}

/// Initialize the tracing subscriber for debug/development logging.
///
/// This is separate from the audit telemetry which goes to syslog.
/// Debug logs go to stderr during initialization only.
///
/// # Verbosity Levels
/// - 0 (default): Only warnings and errors
/// - 1 (-v): Info level
/// - 2 (-vv): Debug level
/// - 3+ (-vvv): Trace level
fn init_tracing(verbose: u8) -> Result<()> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = match verbose {
        0 => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        1 => EnvFilter::new("info"),
        2 => EnvFilter::new("debug"),
        _ => EnvFilter::new("trace"),
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .try_init()
        .context("Failed to initialize tracing subscriber")?;

    Ok(())
}

/// Get the current username for audit logging.
fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}
