//! Launch an interactive shell inside the sandbox WITH network access.
//!
//! Usage (requires root for network namespace):
//!   sudo -E cargo run --example sandbox_shell_network
//!   sudo -E cargo run --example sandbox_shell_network -- /path/to/workdir
//!
//! This creates a full network namespace with veth pairs, letting you test:
//! - Network connectivity through the veth pair
//! - DNS resolution with synthetic resolv.conf
//! - Proxy environment variables (HTTP_PROXY, HTTPS_PROXY)
//!
//! Note: This does NOT start an actual proxy - it just sets up the network
//! namespace and environment. Traffic to the proxy address will fail unless
//! you run a proxy on the host.

use secure_llm::sandbox::bwrap::BwrapBuilder;
use secure_llm::sandbox::ca::{EphemeralCa, find_host_ca_bundle};
use secure_llm::sandbox::netns::{NetnsConfig, NetworkNamespace};
use std::path::Path;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    // Check if running as root
    //    let euid = unsafe { libc::geteuid() };
    //    if euid != 0 {
    //        eprintln!("Error: This example requires root for network namespace creation.");
    //        eprintln!();
    //        eprintln!("Run with:");
    //        eprintln!("  sudo -E cargo run --example sandbox_shell_network");
    //        return ExitCode::from(1);
    //    }

    let work_dir = std::env::args().nth(1).unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .to_string()
    });

    let work_dir = Path::new(&work_dir);

    if !work_dir.exists() {
        eprintln!("Error: Work directory does not exist: {:?}", work_dir);
        return ExitCode::from(1);
    }

    println!("=== Sandbox Shell (with Network) ===");
    println!("Work directory: {:?}", work_dir);
    println!();

    // Create network namespace
    println!("Creating network namespace...");
    let netns_config = NetnsConfig::default();
    let netns = match NetworkNamespace::create(netns_config) {
        Ok(ns) => ns,
        Err(e) => {
            eprintln!("Failed to create network namespace: {}", e);
            return ExitCode::from(1);
        }
    };

    println!("  Network namespace: {}", netns.name);
    println!("  Host IP (proxy):   {}", netns.host_ip);
    println!("  Sandbox IP:        {}", netns.sandbox_ip);
    println!("  Proxy URL:         {}", netns.proxy_url());
    println!();

    // Generate ephemeral CA
    println!("Generating ephemeral CA certificate...");
    let ca = match EphemeralCa::generate() {
        Ok(ca) => ca,
        Err(e) => {
            eprintln!("Failed to generate CA: {}", e);
            return ExitCode::from(1);
        }
    };

    // Create combined CA bundle
    let ca_bundle = if let Some(host_bundle) = find_host_ca_bundle() {
        println!("  Using host CA bundle: {:?}", host_bundle);
        match ca.create_combined_bundle(host_bundle) {
            Ok(bundle) => bundle,
            Err(e) => {
                eprintln!("Failed to create CA bundle: {}", e);
                return ExitCode::from(1);
            }
        }
    } else {
        println!("  No host CA bundle found, using ephemeral CA only");
        ca.cert_path().to_path_buf()
    };

    println!("  CA bundle: {:?}", ca_bundle);
    println!("  Ephemeral CA: {:?}", ca.cert_path());
    println!();

    println!("You're about to enter a sandboxed bash shell with network.");
    println!();
    println!("The sandbox has:");
    println!("  - Read-only access to /usr, /lib, /lib64, /bin, /sbin");
    println!("  - Read-write access to {:?}", work_dir);
    println!("  - Network via veth pair to host");
    println!("  - Proxy env vars pointing to {}", netns.proxy_url());
    println!("  - Custom resolv.conf with Google DNS");
    println!("  - Ephemeral CA injected into trust store");
    println!();
    println!("Useful commands to try:");
    println!("  ip addr                 # See network interfaces");
    println!("  ip route                # See routing table");
    println!("  cat /etc/resolv.conf    # DNS servers");
    println!(
        "  ping {}          # Ping the host (should work)",
        netns.host_ip
    );
    println!("  ping 8.8.8.8            # Ping internet (needs IP forwarding + NAT)");
    println!("  curl -v http://example.com  # HTTP request (will try proxy)");
    println!("  env | grep -i proxy     # See proxy environment");
    println!("  cat /etc/ssl/certs/ca-certificates.crt | tail -30  # See our CA");
    println!();
    println!("Note: Actual internet access requires:");
    println!("  1. IP forwarding enabled: sudo sysctl net.ipv4.ip_forward=1");
    println!("  2. NAT rule: sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -j MASQUERADE");
    println!("  OR a running proxy on {}", netns.proxy_url());
    println!();
    println!("Type 'exit' to leave the sandbox.");
    println!("=========================================");
    println!();

    // Build the bwrap command
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());

    // When running as root (via sudo), we drop privileges to the original user
    // SUDO_UID and SUDO_GID are set by sudo to the invoking user's IDs
    let is_root = unsafe { libc::getuid() } == 0;

    let mut builder = BwrapBuilder::new();

    if is_root {
        // Running as root (via sudo) for network namespace setup
        // Note: bwrap's --unshare-user has permission issues when running as root
        // and trying to bind-mount user-owned directories. For this debug shell,
        // we skip user namespace isolation. The production implementation will
        // use a privileged helper that creates the netns, then spawns an
        // unprivileged process for the actual sandbox.
        println!("  Running as root (user namespace isolation skipped for network mode)");
        builder = builder.unshare_pid();
    } else {
        // Running as regular user - use full user namespace isolation
        builder = builder.unshare_user().map_current_user().unshare_pid();
    }

    builder = builder
        // System directories (read-only)
        .bind_ro(Path::new("/usr"), Path::new("/usr"))
        .bind_ro(Path::new("/lib"), Path::new("/lib"))
        .bind_ro_try(Path::new("/lib64"), Path::new("/lib64"))
        .bind_ro_try(Path::new("/lib32"), Path::new("/lib32"))
        .bind_ro(Path::new("/bin"), Path::new("/bin"))
        .bind_ro_try(Path::new("/sbin"), Path::new("/sbin"))
        .bind_ro_try(
            Path::new("/etc/alternatives"),
            Path::new("/etc/alternatives"),
        )
        .bind_ro_try(Path::new("/etc/ld.so.cache"), Path::new("/etc/ld.so.cache"))
        // Work directory (read-write)
        .bind_rw(work_dir, work_dir)
        // Virtual filesystems
        .tmpfs(Path::new("/tmp"))
        .proc_mount(Path::new("/proc"))
        .dev_minimal()
        // Inject our resolv.conf
        .bind_ro(&netns.resolv_conf_path, Path::new("/etc/resolv.conf"))
        // Inject CA bundle (standard locations)
        .bind_ro(&ca_bundle, Path::new("/etc/ssl/certs/ca-certificates.crt"))
        // Environment - standard vars
        .setenv("HOME", &home)
        .setenv("USER", &user)
        .setenv(
            "PATH",
            "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
        )
        .setenv(
            "TERM",
            &std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string()),
        )
        .setenv("PS1", "\\[\\033[1;32m\\][SANDBOX+NET]\\[\\033[0m\\] \\w $ ")
        // Proxy environment variables
        .setenv("HTTP_PROXY", netns.proxy_url())
        .setenv("HTTPS_PROXY", netns.proxy_url())
        .setenv("http_proxy", netns.proxy_url())
        .setenv("https_proxy", netns.proxy_url())
        .setenv("NO_PROXY", "localhost,127.0.0.1")
        // SSL CA bundle location
        .setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
        .setenv("CURL_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")
        .setenv("REQUESTS_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")
        // Working directory
        .chdir(work_dir)
        // Die when parent dies
        .die_with_parent()
        // Run bash
        .command(Path::new("/bin/bash"), &["--norc".to_string()]);

    // Get the bwrap command line
    let bwrap_cmd = builder.build();
    let bwrap_args: Vec<_> = std::iter::once(bwrap_cmd.get_program().to_os_string())
        .chain(bwrap_cmd.get_args().map(|a| a.to_os_string()))
        .collect();

    // Run bwrap inside the network namespace using `ip netns exec`
    let status = Command::new("ip")
        .args(["netns", "exec", &netns.name])
        .args(&bwrap_args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();

    // Cleanup happens automatically via Drop

    match status {
        Ok(s) if s.success() => {
            println!("\nExited sandbox cleanly.");
            println!("Network namespace and CA cleaned up.");
            ExitCode::SUCCESS
        }
        Ok(s) => {
            println!("\nSandbox exited with: {:?}", s.code());
            ExitCode::from(s.code().unwrap_or(1) as u8)
        }
        Err(e) => {
            eprintln!("\nFailed to run sandbox: {}", e);
            eprintln!();
            eprintln!("Make sure bubblewrap is installed:");
            eprintln!("  sudo apt install bubblewrap");
            ExitCode::from(1)
        }
    }
}
