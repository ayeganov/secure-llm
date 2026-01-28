//! Sandbox orchestration and lifecycle management.
//! 
//! This module coordinates the various components (CA, Proxy, Control Plane, Bwrap)
//! to launch and manage the secure sandbox.

use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{debug, error, info, warn};

use crate::cli::Cli;
use crate::config::{Config, ConfigLoader, ToolProfile};
use crate::control::{ControlPlane, ControlSocketServer, ProxyToTui};
use crate::portmon::{PortBridgeManager, PortDetector};
use crate::proxy::{hold::ConnectionHoldManager, PolicyEngine, ProxyConfig, ProxyServer};
use crate::sandbox::{
    BindMount, EnvContext, expand_env_vars, MountVerifier, SandboxConfig, SandboxLauncher,
    SANDBOX_CA_BUNDLE_PATH, DEFAULT_MAX_PORT_BRIDGES,
    ca::{EphemeralCa, find_host_ca_bundle},
};
use crate::tui::{create_multiplexer, SidecarOptions, SidecarPaneHandle};

/// Action to take after reviewing the startup allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistAction {
    /// Proceed with the existing allowlist.
    Proceed,
    /// User requested to quit.
    Quit,
}

/// Review the startup allowlist and let the user clear/edit it.
///
/// Returns `AllowlistAction::Proceed` to continue or `AllowlistAction::Quit` to exit.
fn review_startup_allowlist(config_loader: &ConfigLoader, headless: bool) -> Result<AllowlistAction> {
    // Skip review in headless mode
    if headless {
        return Ok(AllowlistAction::Proceed);
    }

    // Load existing allowlist
    let allowlist = config_loader.load_user_allowlist().unwrap_or_default();

    // Skip if allowlist is empty
    if allowlist.domains.allowed.is_empty() {
        return Ok(AllowlistAction::Proceed);
    }

    // Display the allowlist
    println!("\n\x1b[1;36m━━━ Persistent Allowlist ━━━\x1b[0m");
    println!("The following domains are permanently allowed:");
    for (i, domain) in allowlist.domains.allowed.iter().enumerate() {
        println!("  \x1b[32m{}\x1b[0m. {}", i + 1, domain);
    }
    println!();
    println!("  \x1b[1m[Enter]\x1b[0m Proceed with existing allowlist");
    println!("  \x1b[1m[c]\x1b[0m     Clear all entries");
    println!("  \x1b[1m[e]\x1b[0m     Edit (remove specific entries)");
    println!("  \x1b[1m[q]\x1b[0m     Quit");
    print!("\n> ");
    std::io::Write::flush(&mut std::io::stdout())?;

    // Read user input
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    match input.as_str() {
        "" => Ok(AllowlistAction::Proceed),
        "c" => {
            config_loader.clear_allowlist()?;
            println!("\x1b[33mCleared all entries from allowlist.\x1b[0m\n");
            Ok(AllowlistAction::Proceed)
        }
        "e" => {
            edit_allowlist(config_loader, &allowlist.domains.allowed)?;
            Ok(AllowlistAction::Proceed)
        }
        "q" => Ok(AllowlistAction::Quit),
        _ => {
            println!("\x1b[33mUnknown option, proceeding with existing allowlist.\x1b[0m\n");
            Ok(AllowlistAction::Proceed)
        }
    }
}

/// Interactive editing of the allowlist (remove specific entries).
fn edit_allowlist(config_loader: &ConfigLoader, domains: &[String]) -> Result<()> {
    println!("\nEnter numbers to remove (comma-separated), or press Enter to cancel:");
    print!("> ");
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();

    if input.is_empty() {
        println!("\x1b[33mNo changes made.\x1b[0m\n");
        return Ok(());
    }

    // Parse numbers
    let mut to_remove: Vec<usize> = Vec::new();
    for part in input.split(',') {
        if let Ok(num) = part.trim().parse::<usize>() {
            if num > 0 && num <= domains.len() {
                to_remove.push(num - 1); // Convert to 0-based index
            }
        }
    }

    // Remove domains in reverse order to maintain indices
    to_remove.sort();
    to_remove.dedup();
    for &idx in to_remove.iter().rev() {
        if idx < domains.len() {
            config_loader.remove_from_allowlist(&domains[idx])?;
            println!("\x1b[31mRemoved:\x1b[0m {}", domains[idx]);
        }
    }

    if !to_remove.is_empty() {
        println!();
    }

    Ok(())
}

/// Run the sandbox orchestration.
pub fn run_sandbox(cli: &Cli, config: &Config, profile: &ToolProfile, config_loader: ConfigLoader) -> Result<()> {
    // Review startup allowlist (user can clear/edit before proceeding)
    match review_startup_allowlist(&config_loader, cli.headless)? {
        AllowlistAction::Proceed => {}
        AllowlistAction::Quit => {
            info!("User chose to quit during allowlist review");
            return Ok(());
        }
    }

    // Check that bwrap is available
    if !crate::sandbox::bwrap_available() {
        anyhow::bail!(
            "Bubblewrap (bwrap) is not installed or not in PATH. Install it with: sudo apt install bubblewrap"
        );
    }

    debug!(
        "Bubblewrap version: {:?}",
        crate::sandbox::bwrap_version()
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

    // Setup Unix socket for TUI IPC
    let tui_socket_path = session_dir.path().join("tui.sock");

    // Create audit logger (syslog integration already initialized)
    let audit = Arc::new(crate::telemetry::AuditLogger::new_null());

    // Setup shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Build tokio runtime for proxy
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to create tokio runtime")?;

    // Create control channel for proxy -> control plane communication
    let (control_tx, control_rx) = mpsc::channel(64);

    // Create proxy configuration
    let proxy_config = ProxyConfig {
        listen_path: socket_path.clone(),
        ca: ca.clone(),
        policy: policy.clone(),
        headless: cli.headless,
        prompt_timeout: Duration::from_secs(config.general.prompt_timeout as u64),
        audit,
        control_tx: Some(control_tx),
    };

    // Start the proxy server in the background
    info!("Starting proxy server on {:?}", socket_path);
    let proxy_server = ProxyServer::new(proxy_config, shutdown_rx.clone());
    let hold_manager = proxy_server.hold_manager();

    let proxy_handle = rt.spawn(async move {
        if let Err(e) = proxy_server.run().await {
            error!("Proxy server error: {}", e);
        }
    });

    // Create portbridge directory with restricted permissions (mode 0700)
    let portbridge_dir = session_dir.path().join("portbridge");
    std::fs::create_dir_all(&portbridge_dir)
        .context("Failed to create portbridge directory")?;
    std::fs::set_permissions(&portbridge_dir, std::fs::Permissions::from_mode(0o700))
        .context("Failed to set portbridge directory permissions")?;
    debug!("Created portbridge directory: {:?}", portbridge_dir);

    // Create port event channel (sender will be used by detector, receiver by control plane)
    let (port_event_tx, port_event_rx) = mpsc::channel(32);

    // Create bridge manager (will be connected after sandbox starts)
    let bridge_manager = Arc::new(Mutex::new(
        PortBridgeManager::new(portbridge_dir.clone(), DEFAULT_MAX_PORT_BRIDGES)
    ));

    // Setup TUI sidecar and control plane
    let (control_handle, _sidecar_pane): (_, Option<Box<dyn SidecarPaneHandle>>) =
        if !cli.headless {
            match create_multiplexer() {
                Some(mux) => {
                    info!(
                        "Setting up TUI sidecar with Unix socket IPC (multiplexer: {})",
                        mux.kind()
                    );

                    let socket_server = ControlSocketServer::new(&tui_socket_path)
                        .context("Failed to create TUI socket server")?;

                    let exe_path =
                        std::env::current_exe().context("Failed to get current executable path")?;

                    let tui_command = format!(
                        "{} internal-tui --socket-path {}",
                        exe_path.display(),
                        tui_socket_path.display()
                    );

                    let options = SidecarOptions {
                        height: Some(15),
                        command: Some(tui_command),
                        focus: false,
                    };

                    let sidecar = mux
                        .create_sidecar_pane(options)
                        .context("Failed to create TUI sidecar pane")?;
                    info!("Created TUI sidecar pane: {}", sidecar.pane_id());

                    let control_shutdown_rx = shutdown_rx.clone();
                    let control_policy = policy.clone();
                    let control_hold_manager = hold_manager.clone();
                    let control_bridge_manager = bridge_manager.clone();
                    let control_config_loader = config_loader;

                    let handle = rt.spawn(async move {
                        let accept_result = tokio::time::timeout(
                            Duration::from_secs(10),
                            socket_server.accept(),
                        )
                        .await;

                        match accept_result {
                            Ok(Ok((proxy_tx, tui_rx))) => {
                                info!("TUI connected to control socket");
                                let control_plane = ControlPlane::new_with_socket(
                                    proxy_tx,
                                    tui_rx,
                                    control_rx,
                                    control_hold_manager,
                                    control_policy,
                                    control_shutdown_rx,
                                )
                                .with_config_loader(control_config_loader)
                                .with_bridge_manager(control_bridge_manager)
                                .with_port_events(port_event_rx);
                                control_plane.run().await;
                            }
                            _ => {
                                warn!("TUI connection failed/timeout, running in headless mode");
                                run_headless_control_plane(
                                    control_rx,
                                    control_hold_manager,
                                    control_shutdown_rx,
                                )
                                .await;
                            }
                        }
                    });

                    (handle, Some(sidecar))
                }
                None => {
                    warn!("TUI not available: not running in a terminal multiplexer (tmux/zellij). Unknown domains will be blocked.");
                    let control_shutdown_rx = shutdown_rx.clone();
                    let control_hold_manager = hold_manager.clone();
                    let handle = rt.spawn(async move {
                        run_headless_control_plane(control_rx, control_hold_manager, control_shutdown_rx).await;
                    });
                    (handle, None)
                }
            }
        } else {
            let control_shutdown_rx = shutdown_rx.clone();
            let control_hold_manager = hold_manager.clone();
            let handle = rt.spawn(async move {
                run_headless_control_plane(control_rx, control_hold_manager, control_shutdown_rx).await;
            });
            (handle, None)
        };

    std::thread::sleep(Duration::from_millis(100));

    let tool_binary =
        resolve_tool_binary(&profile.tool.binary).context("Failed to resolve tool binary")?;

    info!("Tool binary: {:?}", tool_binary);

    let mount_verifier = MountVerifier::new(&config.filesystem.denylist)
        .context("Failed to create mount verifier")?;

    let env_context = EnvContext {
        ca_cert_path: PathBuf::from(SANDBOX_CA_BUNDLE_PATH),
        work_dir: work_dir.clone(),
        proxy_addr: "http://127.0.0.1:8080".to_string(),
    };
    // Merge base sandbox env (from config) with profile-specific env
    // Profile env takes precedence over base config
    let mut merged_env = config.sandbox.env.clone();
    merged_env.extend(profile.environment.clone());
    let env = expand_env_vars(&merged_env, &env_context);

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

    for dir in collect_tool_mount_dirs(&tool_binary) {
        bind_ro.push(BindMount::same(dir));
    }

    bind_rw.push(BindMount::same(work_dir.clone()));

    let sandbox_config = SandboxConfig {
        tool_binary,
        tool_args: cli.tool_args.clone(),
        work_dir,
        env,
        bind_rw,
        bind_ro,
        ca_bundle_path,
        resolv_conf_path,
        proxy_socket_path: Some(socket_path),
        portbridge_dir: Some(portbridge_dir.clone()),
        max_port_bridges: DEFAULT_MAX_PORT_BRIDGES,
        extra_flags: vec![],
    };

    info!("Launching sandbox...");
    let launcher = SandboxLauncher::new(mount_verifier);
    let mut handle = launcher
        .launch(sandbox_config)
        .context("Failed to launch sandbox")?;

    info!("Sandbox started with PID: {}", handle.pid);

    // Start port detector (runs on host, reads /proc/<pid>/net/tcp)
    let detector = PortDetector::new(handle.pid, Duration::from_secs(2));
    let detector_shutdown = shutdown_rx.clone();

    let detector_handle = rt.spawn(async move {
        detector.run(port_event_tx, detector_shutdown).await;
    });

    // Connect bridge manager to reverse shim (with retry)
    let bridge_manager_clone = bridge_manager.clone();
    let bridge_connect_handle = rt.spawn(async move {
        // Wait for reverse shim to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut manager = bridge_manager_clone.lock().await;
        match manager.connect_control().await {
            Ok(()) => {
                info!("Connected to reverse shim control socket");
            }
            Err(e) => {
                warn!("Failed to connect to reverse shim control socket: {}", e);
            }
        }
    });

    // Handle pre-configured port mappings (--publish flag)
    let port_mappings = cli.port_mappings();
    if !port_mappings.is_empty() {
        let bridge_manager_publish = bridge_manager.clone();
        let mappings = port_mappings.clone();
        rt.spawn(async move {
            // Wait for bridge manager connection
            tokio::time::sleep(Duration::from_secs(1)).await;

            let mut manager = bridge_manager_publish.lock().await;
            if manager.is_connected() {
                for (host_port, container_port) in mappings {
                    if let Err(e) = manager.start_bridge(host_port, container_port).await {
                        warn!(
                            "Failed to start pre-configured port bridge {}:{}: {}",
                            host_port, container_port, e
                        );
                    } else {
                        info!("Started pre-configured port bridge {}:{}", host_port, container_port);
                    }
                }
            }
        });
    }

    let status = handle.wait().context("Failed to wait for sandbox")?;
    let _ = shutdown_tx.send(true);

    // Shutdown bridge manager
    {
        let manager = rt.block_on(async { bridge_manager.lock().await });
        manager.shutdown_all();
    }

    rt.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(2), proxy_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), control_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), detector_handle).await;
        let _ = tokio::time::timeout(Duration::from_millis(500), bridge_connect_handle).await;
    });

    if status.success() {
        info!("Sandbox exited successfully");
        Ok(())
    } else {
        let code = status.code().unwrap_or(-1);
        anyhow::bail!("Sandbox exited with code {}", code)
    }
}

/// Run the control plane in headless mode (no TUI connection).
async fn run_headless_control_plane(
    mut control_rx: mpsc::Receiver<ProxyToTui>,
    hold_manager: Arc<ConnectionHoldManager>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    use crate::proxy::hold::ConnectionDecision;
    info!("Running control plane in headless mode (auto-deny)");
    loop {
        tokio::select! {
            msg = control_rx.recv() => {
                match msg {
                    Some(ProxyToTui::PermissionRequest { id, domain, port, .. }) => {
                        warn!("Auto-denying permission request for {}:{} (headless mode)", domain, port);
                        let _ = hold_manager.decide(id, ConnectionDecision::Block);
                    }
                    Some(_) => {} // Ignore other messages
                    None => break,
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
        }
    }
}

fn create_resolv_conf(session_dir: &Path) -> Result<PathBuf> {
    let resolv_path = session_dir.join("resolv.conf");
    let content = if let Ok(resolved_conf) = std::fs::read_to_string("/run/systemd/resolve/resolv.conf") {
        resolved_conf
    } else {
        "# Generated by secure-llm\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n".to_string()
    };
    std::fs::write(&resolv_path, content).context("Failed to write resolv.conf")?;
    Ok(resolv_path)
}

fn resolve_tool_binary(binary: &str) -> Result<PathBuf> {
    let path = PathBuf::from(binary);
    if path.is_absolute() {
        if path.exists() { Ok(path) } else { anyhow::bail!("Tool binary not found: {:?}", path) }
    } else if binary.contains('/') || binary.contains('\\') {
        let absolute = std::fs::canonicalize(&path).with_context(|| format!("Tool binary not found: {:?}", path))?;
        Ok(absolute)
    } else {
        match which::which(binary) {
            Ok(p) => Ok(p),
            Err(e) => anyhow::bail!("Tool '{}' not found in PATH: {}", binary, e),
        }
    }
}

fn collect_tool_mount_dirs(tool_binary: &Path) -> std::vec::Vec<PathBuf> {
    let mut collected_mount_dirs = std::vec::Vec::new();
    let is_system_path = |p: &Path| p.starts_with("/usr") || p.starts_with("/bin") || p.starts_with("/sbin");
    if let Some(tool_dir) = tool_binary.parent() && !is_system_path(tool_dir) {
        collected_mount_dirs.push(tool_dir.to_path_buf());
    }
    if let Ok(resolved) = std::fs::canonicalize(tool_binary) 
        && resolved != tool_binary 
        && let Some(resolved_dir) = resolved.parent() 
        && !is_system_path(resolved_dir) 
        && !collected_mount_dirs.contains(&resolved_dir.to_path_buf()) {
            collected_mount_dirs.push(resolved_dir.to_path_buf());
    }
    collected_mount_dirs
}

fn merge_profile_network_config(
    base: &crate::config::NetworkConfig,
    profile: &ToolProfile,
) -> crate::config::NetworkConfig {
    let mut merged = base.clone();
    merged.allowlist.extend(profile.network.allowlist.clone());
    merged.host_rewrite.extend(profile.proxy.host_rewrite.clone());
    merged
}
