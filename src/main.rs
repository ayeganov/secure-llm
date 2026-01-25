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
    cli::{Cli, Commands},
    config::{Config, ConfigLoader, ToolProfile},
    proxy::{PolicyEngine, ProxyConfig, ProxyServer},
    sandbox::{
        MountVerifier, SandboxConfig, SandboxLauncher, SANDBOX_CA_BUNDLE_PATH,
        bwrap::{BindMount, EnvContext, expand_env_vars},
        ca::{EphemeralCa, find_host_ca_bundle},
    },
    shim,
    telemetry::{self, AuditEvent, AuditLogger},
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

fn main() -> Result<()> {
    // Parse CLI arguments first (before any other initialization)
    let cli = Cli::parse();

    // Handle internal subcommands first (before full initialization)
    if let Some(command) = cli.command {
        return handle_command(command);
    }

    // Normal sandbox mode - tool is required
    let tool = cli
        .tool
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("A tool name is required. Usage: secure-llm <TOOL>"))?;

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
        .load_profile(tool, cli.profile.as_deref())
        .context("Failed to load tool profile")?;

    info!(
        "Using profile '{}' for tool '{}'",
        profile.tool.display_name, tool
    );

    // Record session start time
    let session_start = Instant::now();

    // Log session start to syslog
    telemetry::audit().log(AuditEvent::SessionStart {
        user: whoami(),
        tool: tool.to_string(),
        pid: std::process::id(),
    });

    // Run the sandbox - this is the main orchestration
    let result = run_sandbox(&cli, &config, &profile);

    // Calculate session duration
    let duration_sec = session_start.elapsed().as_secs();

    // Log session end to syslog
    telemetry::audit().log(AuditEvent::SessionEnd {
        user: whoami(),
        tool: tool.to_string(),
        duration_sec,
    });

    result
}

/// Handle subcommands (internal shim, etc.).
///
/// These commands are lightweight and don't need full telemetry/config initialization.
fn handle_command(command: Commands) -> Result<()> {
    match command {
        Commands::InternalShim { socket_path } => {
            // Run the egress shim - this is a minimal async runtime
            // Don't initialize full logging/telemetry to keep it lightweight
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?;

            rt.block_on(async {
                shim::run(&socket_path)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            })
        }
    }
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
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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

/// Run the sandbox orchestration.
///
/// This is the main orchestration function that:
/// 1. Generates ephemeral CA for TLS interception
/// 2. Creates combined CA bundle (host CAs + ephemeral CA)
/// 3. Creates synthetic resolv.conf for DNS
/// 4. Starts the proxy server on Unix socket
/// 5. Launches the sandbox with the tool
/// 6. Waits for completion and cleans up
fn run_sandbox(cli: &Cli, config: &Config, profile: &ToolProfile) -> Result<()> {
    // Check that bwrap is available
    if !secure_llm::sandbox::bwrap_available() {
        anyhow::bail!(
            "Bubblewrap (bwrap) is not installed or not in PATH.\n\
             Install it with: sudo apt install bubblewrap"
        );
    }

    debug!(
        "Bubblewrap version: {:?}",
        secure_llm::sandbox::bwrap_version()
    );

    // Get working directory
    let work_dir = std::env::current_dir().context("Failed to get current directory")?;
    info!("Working directory: {:?}", work_dir);

    // Create temporary directory for session resources
    let session_dir = tempfile::Builder::new()
        .prefix("secure-llm-")
        .tempdir()
        .context("Failed to create session directory")?;

    debug!("Session directory: {:?}", session_dir.path());

    // Generate ephemeral CA for TLS interception
    info!("Generating ephemeral CA certificate...");
    let ca = EphemeralCa::generate().context("Failed to generate ephemeral CA")?;
    let ca = Arc::new(ca);

    // Create combined CA bundle (host CAs + our ephemeral CA)
    let ca_bundle_path = if let Some(host_bundle) = find_host_ca_bundle() {
        debug!("Using host CA bundle: {:?}", host_bundle);
        ca.create_combined_bundle(host_bundle)
            .context("Failed to create combined CA bundle")?
    } else {
        warn!("No host CA bundle found, using ephemeral CA only");
        ca.cert_path().to_path_buf()
    };

    // Create synthetic resolv.conf for DNS
    // On modern Linux (systemd-resolved), /etc/resolv.conf points to 127.0.0.53
    // which doesn't work inside the sandbox's network namespace
    let resolv_conf_path =
        create_resolv_conf(session_dir.path()).context("Failed to create synthetic resolv.conf")?;

    // Create policy engine from merged config (base config + profile-specific rules)
    let merged_network = merge_profile_network_config(&config.network, profile);
    let cli_allow: Vec<String> = cli.allow_domains.clone();
    let policy = Arc::new(PolicyEngine::from_config(&merged_network, &cli_allow));

    info!(
        "Policy engine: {} allowlist, {} blocklist, {} graylist entries",
        merged_network.allowlist.len(),
        merged_network.blocklist.len(),
        merged_network.graylist.len()
    );

    // Setup Unix socket for proxy
    let socket_path = session_dir.path().join("proxy.sock");

    // Create audit logger (syslog integration already initialized)
    let audit = Arc::new(AuditLogger::new_null()); // TODO: Use real audit logger

    // Setup shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Create proxy configuration
    let proxy_config = ProxyConfig {
        listen_path: socket_path.clone(),
        ca: ca.clone(),
        policy: policy.clone(),
        headless: cli.headless,
        prompt_timeout: Duration::from_secs(config.general.prompt_timeout as u64),
        audit,
    };

    // Build tokio runtime for proxy
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to create tokio runtime")?;

    // Start the proxy server in the background
    info!("Starting proxy server on {:?}", socket_path);
    let proxy_server = ProxyServer::new(proxy_config, shutdown_rx);
    let proxy_handle = rt.spawn(async move {
        if let Err(e) = proxy_server.run().await {
            error!("Proxy server error: {}", e);
        }
    });

    // Give the proxy a moment to start
    std::thread::sleep(Duration::from_millis(100));

    // Resolve tool binary path
    let tool_binary =
        resolve_tool_binary(&profile.tool.binary).context("Failed to resolve tool binary")?;

    info!("Tool binary: {:?}", tool_binary);

    // Create mount verifier
    let mount_verifier = MountVerifier::new(&config.filesystem.denylist)
        .context("Failed to create mount verifier")?;

    // Expand environment variables with sandbox context
    // Note: ca_cert_path uses the sandbox path (where it's mounted), not the host path
    let env_context = EnvContext {
        ca_cert_path: PathBuf::from(SANDBOX_CA_BUNDLE_PATH),
        work_dir: work_dir.clone(),
        proxy_addr: "http://127.0.0.1:8080".to_string(), // Shim listens here inside sandbox
    };
    let env = expand_env_vars(&profile.environment, &env_context);

    // Build sandbox configuration
    // Start with bind mounts from config
    let mut bind_ro: Vec<BindMount> = config
        .filesystem
        .bind_ro
        .iter()
        .map(|p| BindMount::same(p.clone()))
        .collect();
    let mut bind_rw: Vec<BindMount> = config
        .filesystem
        .bind_rw
        .iter()
        .map(|p| BindMount::same(p.clone()))
        .collect();

    // Include directories needed for the tool binary (handles symlinks)
    for dir in collect_tool_mount_dirs(&tool_binary) {
        bind_ro.push(BindMount::same(dir));
    }

    // Always include working directory as read-write
    bind_rw.push(BindMount::same(work_dir.clone()));

    let sandbox_config = SandboxConfig {
        tool_binary,
        tool_args: cli.tool_args.clone(),
        work_dir: work_dir.clone(),
        env,
        bind_rw,
        bind_ro,
        ca_bundle_path,
        resolv_conf_path,
        proxy_socket_path: Some(socket_path),
        extra_flags: vec![],
    };

    // Launch the sandbox
    info!("Launching sandbox...");
    let launcher = SandboxLauncher::new(mount_verifier);
    let mut handle = launcher
        .launch(sandbox_config)
        .context("Failed to launch sandbox")?;

    info!("Sandbox started with PID: {}", handle.pid);

    // Wait for sandbox to exit
    let status = handle.wait().context("Failed to wait for sandbox")?;

    // Signal proxy to shutdown
    let _ = shutdown_tx.send(true);

    // Wait for proxy to stop (with timeout)
    rt.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(2), proxy_handle).await;
    });

    // Session dir is automatically cleaned up when tempdir goes out of scope

    if status.success() {
        info!("Sandbox exited successfully");
        Ok(())
    } else {
        let code = status.code().unwrap_or(-1);
        anyhow::bail!("Sandbox exited with code {}", code)
    }
}

/// Create a synthetic resolv.conf with real DNS servers.
///
/// On modern Linux systems with systemd-resolved, /etc/resolv.conf often points
/// to 127.0.0.53. This doesn't work inside the sandbox's network namespace because
/// that address doesn't exist there.
///
/// This function creates a resolv.conf with actual DNS servers.
fn create_resolv_conf(session_dir: &std::path::Path) -> Result<PathBuf> {
    let resolv_path = session_dir.join("resolv.conf");

    // Try to read systemd-resolved's upstream servers first
    let content =
        if let Ok(resolved_conf) = std::fs::read_to_string("/run/systemd/resolve/resolv.conf") {
            // Use systemd-resolved's upstream config (has real DNS servers)
            resolved_conf
        } else {
            // Fallback to common public DNS servers
            "# Generated by secure-llm\n\
         nameserver 8.8.8.8\n\
         nameserver 8.8.4.4\n\
         nameserver 1.1.1.1\n"
                .to_string()
        };

    std::fs::write(&resolv_path, content).context("Failed to write resolv.conf")?;
    debug!("Created synthetic resolv.conf at {:?}", resolv_path);

    Ok(resolv_path)
}

/// Resolve a tool binary name to its full path.
///
/// If the binary is a simple name (no path separator), search PATH.
/// Otherwise, use it as-is.
fn resolve_tool_binary(binary: &str) -> Result<PathBuf> {
    let path = PathBuf::from(binary);

    if path.is_absolute() {
        // Already absolute path
        if path.exists() {
            Ok(path)
        } else {
            anyhow::bail!("Tool binary not found: {:?}", path)
        }
    } else if binary.contains('/') || binary.contains('\\') {
        // Relative path with directory component
        let absolute = std::fs::canonicalize(&path)
            .with_context(|| format!("Tool binary not found: {:?}", path))?;
        Ok(absolute)
    } else {
        // Simple binary name - search PATH
        which::which(binary).with_context(|| format!("Tool '{}' not found in PATH", binary))
    }
}

/// Collect directories needed to mount a tool binary into the sandbox.
///
/// Tools like `claude` are often symlinks:
///   ~/.local/bin/claude -> ~/.local/share/claude/versions/2.1.19
///
/// For the sandbox to execute the tool, we need to mount both:
/// 1. The directory containing the symlink (so the path resolves)
/// 2. The directory containing the actual binary (so the target exists)
///
/// This function returns all directories that need to be mounted,
/// excluding standard system paths that are already mounted.
fn collect_tool_mount_dirs(tool_binary: &std::path::Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    let is_system_path = |p: &std::path::Path| {
        p.starts_with("/usr") || p.starts_with("/bin") || p.starts_with("/sbin")
    };

    // Add the directory containing the tool binary (or symlink)
    if let Some(tool_dir) = tool_binary.parent() {
        if !is_system_path(tool_dir) {
            dirs.push(tool_dir.to_path_buf());
        }
    }

    // If it's a symlink, also add the directory containing the target
    if let Ok(resolved) = std::fs::canonicalize(tool_binary) {
        if resolved != tool_binary {
            if let Some(resolved_dir) = resolved.parent() {
                if !is_system_path(resolved_dir) && !dirs.contains(&resolved_dir.to_path_buf()) {
                    debug!(
                        "Tool binary is symlink, also mounting target: {:?} -> {:?}",
                        tool_binary, resolved_dir
                    );
                    dirs.push(resolved_dir.to_path_buf());
                }
            }
        }
    }

    dirs
}

/// Merge a tool profile's network configuration into the base network config.
///
/// Tool profiles (Claude, Gemini, Cursor, etc.) define tool-specific domains
/// that need to be allowed for the tool to function. For example:
/// - Claude needs `*.anthropic.com`
/// - Gemini needs `*.googleapis.com`, `oauth2.googleapis.com`
///
/// This function merges the profile's allowlist and host_rewrite rules into
/// the base network configuration, producing a combined policy.
fn merge_profile_network_config(
    base: &secure_llm::config::NetworkConfig,
    profile: &ToolProfile,
) -> secure_llm::config::NetworkConfig {
    let mut merged = base.clone();
    merged.allowlist.extend(profile.network.allowlist.clone());
    merged.host_rewrite.extend(profile.proxy.host_rewrite.clone());
    merged
}
