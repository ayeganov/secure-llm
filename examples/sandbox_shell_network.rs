//! Launch an interactive shell inside the sandbox WITH network access.
//!
//! This example demonstrates the rootless socket shim architecture:
//! - NO sudo/root required
//! - NO veth pairs or network namespaces with `ip` commands
//! - Proxy listens on Unix socket, bind-mounted into sandbox
//! - Egress shim inside sandbox forwards TCP to Unix socket
//!
//! Usage:
//!   cargo run --example sandbox_shell_network
//!   cargo run --example sandbox_shell_network -- /path/to/workdir
//!
//! Architecture:
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Sandbox (rootless)                       │
//! │                                                             │
//! │   ┌──────────────┐         ┌───────────────────────────┐   │
//! │   │  bash        │ HTTP    │     EgressShim            │   │
//! │   │  curl, etc   │ PROXY   │  TCP 127.0.0.1:8080       │   │
//! │   │              │────────►│         │                 │   │
//! │   └──────────────┘         │         ▼                 │   │
//! │                            │  /tmp/proxy.sock ─────────┼───┼──┐
//! │                            └───────────────────────────┘   │  │
//! └─────────────────────────────────────────────────────────────┘  │
//!                                                                  │
//! ┌────────────────────────────────────────────────────────────────┼──┐
//! │                     Host                                       │  │
//! │                                                                │  │
//! │   ┌───────────────────────────────────────────────────────┐    │  │
//! │   │               ProxyServer                             │◄───┘  │
//! │   │           Unix Socket Listener                        │       │
//! │   │        /tmp/secure-llm/proxy.sock                     │       │
//! │   │                    │                                  │       │
//! │   │                    ▼                                  │       │
//! │   │              (to internet)                            │       │
//! │   └───────────────────────────────────────────────────────┘       │
//! └────────────────────────────────────────────────────────────────────┘
//! ```

use secure_llm::config::NetworkConfig;
use secure_llm::proxy::{PolicyEngine, ProxyConfig, ProxyServer};
use secure_llm::sandbox::bwrap::BwrapBuilder;
use secure_llm::sandbox::ca::{find_host_ca_bundle, EphemeralCa};
use secure_llm::telemetry::AuditLogger;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("secure_llm=debug".parse().unwrap())
                .add_directive("hyper=info".parse().unwrap()),
        )
        .init();

    let work_dir = std::env::args().nth(1).unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .to_string()
    });

    let work_dir = Path::new(&work_dir);

    if !work_dir.exists() {
        eprintln!("Error: Work directory does not exist: {:?}", work_dir);
        return std::process::ExitCode::from(1);
    }

    println!("=== Sandbox Shell (Rootless Network via Socket Shim) ===");
    println!("Work directory: {:?}", work_dir);
    println!();

    // Generate ephemeral CA for TLS interception
    println!("Generating ephemeral CA certificate...");
    let ca = match EphemeralCa::generate() {
        Ok(ca) => Arc::new(ca),
        Err(e) => {
            eprintln!("Failed to generate CA: {}", e);
            return std::process::ExitCode::from(1);
        }
    };

    // Create combined CA bundle (host CAs + our ephemeral CA)
    let ca_bundle = if let Some(host_bundle) = find_host_ca_bundle() {
        println!("  Using host CA bundle: {:?}", host_bundle);
        match ca.create_combined_bundle(host_bundle) {
            Ok(bundle) => bundle,
            Err(e) => {
                eprintln!("Failed to create CA bundle: {}", e);
                return std::process::ExitCode::from(1);
            }
        }
    } else {
        println!("  No host CA bundle found, using ephemeral CA only");
        ca.cert_path().to_path_buf()
    };

    println!("  CA bundle: {:?}", ca_bundle);
    println!("  Ephemeral CA: {:?}", ca.cert_path());
    println!();

    // Create policy engine with allowlist
    println!("Setting up policy engine...");
    let network_config = NetworkConfig {
        allowlist: vec![
            // Common package registries
            "pypi.org".to_string(),
            "*.pypi.org".to_string(),
            "files.pythonhosted.org".to_string(),
            "registry.npmjs.org".to_string(),
            "crates.io".to_string(),
            "*.crates.io".to_string(),
            "static.crates.io".to_string(),
            // GitHub
            "github.com".to_string(),
            "*.github.com".to_string(),
            "api.github.com".to_string(),
            // Anthropic
            "api.anthropic.com".to_string(),
            "*.anthropic.com".to_string(),
            // OpenAI
            "api.openai.com".to_string(),
            // General utilities for testing
            "example.com".to_string(),
            "www.example.com".to_string(),
            "httpbin.org".to_string(),
            "ifconfig.me".to_string(),
        ],
        blocklist: vec![
            "malware.example.com".to_string(),
        ],
        graylist: vec![
            "raw.githubusercontent.com".to_string(),
        ],
        host_rewrite: Default::default(),
    };

    let cli_allow: Vec<String> = vec![];
    let policy = Arc::new(PolicyEngine::from_config(&network_config, &cli_allow));
    println!("  Allowlist: {} domains", network_config.allowlist.len());
    println!("  Blocklist: {} domains", network_config.blocklist.len());
    println!("  Graylist: {} domains", network_config.graylist.len());
    println!();

    // Create audit logger (null logger for example)
    let audit = Arc::new(AuditLogger::new_null());

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Setup Unix socket for proxy
    let socket_dir = PathBuf::from("/tmp/secure-llm");
    if let Err(e) = std::fs::create_dir_all(&socket_dir) {
        eprintln!("Failed to create socket directory: {}", e);
        return std::process::ExitCode::from(1);
    }
    let socket_path = socket_dir.join("proxy.sock");

    // Remove stale socket if exists
    let _ = std::fs::remove_file(&socket_path);

    let proxy_config = ProxyConfig {
        listen_path: socket_path.clone(),
        ca: ca.clone(),
        policy: policy.clone(),
        headless: true, // Block unknown domains (no TUI in this example)
        prompt_timeout: Duration::from_secs(30),
        audit,
    };

    // Start the proxy server
    println!("Starting proxy server...");
    println!("  Socket: {:?}", socket_path);
    let proxy_server = ProxyServer::new(proxy_config, shutdown_rx);
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy_server.run().await {
            eprintln!("Proxy server error: {}", e);
        }
    });

    // Give the proxy a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    println!("  Proxy server started!");
    println!();

    // Get the path to our own binary (for the shim)
    let self_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Failed to get current executable path: {}", e);
            return std::process::ExitCode::from(1);
        }
    };

    // For the example, we need to use the built binary, not the example binary
    // The shim command is in the main secure-llm binary
    let secure_llm_bin = self_exe
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("secure-llm"))
        .unwrap_or_else(|| PathBuf::from("./target/debug/secure-llm"));

    if !secure_llm_bin.exists() {
        eprintln!("Error: secure-llm binary not found at {:?}", secure_llm_bin);
        eprintln!("Please run 'cargo build' first.");
        return std::process::ExitCode::from(1);
    }

    println!("Using secure-llm binary: {:?}", secure_llm_bin);
    println!();

    println!("You're about to enter a sandboxed bash shell with network.");
    println!();
    println!("The sandbox has:");
    println!("  - Read-only access to /usr, /lib, /lib64, /bin, /sbin");
    println!("  - Read-write access to {:?}", work_dir);
    println!("  - Empty network namespace (--unshare-net)");
    println!("  - Egress shim forwarding 127.0.0.1:8080 -> Unix socket");
    println!("  - Proxy with TLS interception on Unix socket");
    println!("  - Ephemeral CA injected into trust store");
    println!();
    println!("Useful commands to try:");
    println!("  curl -v https://example.com        # HTTPS via proxy (allowed)");
    println!("  curl -v https://httpbin.org/ip     # Check your IP (allowed)");
    println!("  curl -v https://evil.com           # Will be BLOCKED by policy");
    println!("  curl -v http://ifconfig.me         # HTTP via proxy (allowed)");
    println!("  env | grep -i proxy                # See proxy environment vars");
    println!("  cat /etc/ssl/certs/ca-certificates.crt | tail -30  # See our CA");
    println!("  ip addr                            # Only loopback (no veth!)");
    println!();
    println!("Note: ping won't work (no raw sockets), but HTTP/HTTPS will!");
    println!();
    println!("Type 'exit' to leave the sandbox.");
    println!("=========================================");
    println!();

    // Build the bwrap command with rootless socket shim
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());

    // The shim command that runs inside the sandbox
    // Note: We mount secure-llm to /opt/secure-llm since /bin is read-only
    let shim_and_shell = format!(
        "/opt/secure-llm internal-shim /tmp/proxy.sock & exec /bin/bash --norc"
    );

    let builder = BwrapBuilder::new()
        // Namespace isolation (rootless!)
        .unshare_user()
        .map_current_user()
        .unshare_pid()
        .unshare_net() // Empty network namespace - only loopback
        // System directories (read-only)
        .bind_ro(Path::new("/usr"), Path::new("/usr"))
        .bind_ro(Path::new("/lib"), Path::new("/lib"))
        .bind_ro_try(Path::new("/lib64"), Path::new("/lib64"))
        .bind_ro_try(Path::new("/lib32"), Path::new("/lib32"))
        .bind_ro(Path::new("/bin"), Path::new("/bin"))
        .bind_ro_try(Path::new("/sbin"), Path::new("/sbin"))
        .bind_ro_try(Path::new("/etc/alternatives"), Path::new("/etc/alternatives"))
        .bind_ro_try(Path::new("/etc/ld.so.cache"), Path::new("/etc/ld.so.cache"))
        // Work directory (read-write)
        .bind_rw(work_dir, work_dir)
        // Virtual filesystems
        .tmpfs(Path::new("/tmp"))
        .proc_mount(Path::new("/proc"))
        .dev_minimal()
        // === ROOTLESS SOCKET SHIM SETUP ===
        // Bind-mount the proxy Unix socket into the sandbox
        .bind_rw(&socket_path, Path::new("/tmp/proxy.sock"))
        // Bind-mount the secure-llm binary (for running the shim)
        // Note: Can't use /bin since it's read-only, so we use /opt
        .bind_ro(&secure_llm_bin, Path::new("/opt/secure-llm"))
        // Inject CA bundle
        .bind_ro(&ca_bundle, Path::new("/etc/ssl/certs/ca-certificates.crt"))
        // Environment - standard vars
        .setenv("HOME", &home)
        .setenv("USER", &user)
        .setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin")
        .setenv("TERM", &std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string()))
        .setenv("PS1", "\\[\\033[1;32m\\][SANDBOX+NET]\\[\\033[0m\\] \\w $ ")
        // Proxy environment - points to the shim's TCP listener
        .setenv("HTTP_PROXY", "http://127.0.0.1:8080")
        .setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
        .setenv("http_proxy", "http://127.0.0.1:8080")
        .setenv("https_proxy", "http://127.0.0.1:8080")
        .setenv("NO_PROXY", "localhost")
        // SSL CA bundle location
        .setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
        .setenv("CURL_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")
        .setenv("REQUESTS_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")
        // Working directory
        .chdir(work_dir)
        // Die when parent dies
        .die_with_parent()
        // Run the shim in background, then bash
        .command(Path::new("/bin/sh"), &["-c".to_string(), shim_and_shell]);

    let mut cmd = builder.build();

    // Run the sandbox (blocking)
    let status = tokio::task::spawn_blocking(move || {
        cmd.stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
    })
    .await
    .expect("Failed to spawn blocking task");

    // Signal proxy to shutdown
    let _ = shutdown_tx.send(true);

    // Wait for proxy to stop
    let _ = proxy_handle.await;

    // Cleanup socket
    let _ = std::fs::remove_file(&socket_path);

    match status {
        Ok(s) if s.success() => {
            println!("\nExited sandbox cleanly.");
            println!("Proxy and CA cleaned up.");
            std::process::ExitCode::SUCCESS
        }
        Ok(s) => {
            println!("\nSandbox exited with: {:?}", s.code());
            std::process::ExitCode::from(s.code().unwrap_or(1) as u8)
        }
        Err(e) => {
            eprintln!("\nFailed to run sandbox: {}", e);
            eprintln!();
            eprintln!("Make sure bubblewrap is installed:");
            eprintln!("  sudo apt install bubblewrap");
            std::process::ExitCode::from(1)
        }
    }
}
