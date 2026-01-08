//! Network namespace setup for sandbox isolation.
//!
//! This module creates isolated network namespaces with veth pairs for routing
//! sandbox traffic through the MITM proxy.
//!
//! # Network Architecture
//!
//! ```text
//! Host Network Namespace          Sandbox Network Namespace
//! ─────────────────────────────   ─────────────────────────────
//!
//!         eth0 (internet)               veth-sandbox
//!             │                             │
//!             │                             │ 10.200.0.2/24
//!             ▼                             │
//!        ┌─────────┐                        │
//!        │  Proxy  │◄──── veth-host ────────┘
//!        │ :8080   │      10.200.0.1/24
//!        └─────────┘
//!             │
//!             ▼
//!        (to internet)
//! ```
//!
//! # The resolv.conf Problem
//!
//! On modern Linux systems with systemd-resolved, `/etc/resolv.conf` points to
//! `127.0.0.53`. Inside our network namespace, this address doesn't exist,
//! causing DNS lookups to hang for 30 seconds and then fail.
//!
//! **Solution**: We generate a synthetic `resolv.conf` with real DNS servers
//! (configurable, defaults to Google DNS) and bind-mount it inside the sandbox.
//!
//! # Requirements
//!
//! - `CAP_NET_ADMIN` capability or root access
//! - `ip` command available in PATH
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::sandbox::netns::{NetworkNamespace, NetnsConfig};
//!
//! let config = NetnsConfig::default();
//! let netns = NetworkNamespace::create(config)?;
//!
//! // Use with bubblewrap
//! bwrap_builder.join_netns(netns.path());
//!
//! // Set proxy environment variables
//! env.insert("HTTP_PROXY", netns.proxy_url());
//! env.insert("HTTPS_PROXY", netns.proxy_url());
//! ```

use super::error::NetnsError;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

/// Configuration for the network namespace.
#[derive(Debug, Clone)]
pub struct NetnsConfig {
    /// Name for the namespace (used for /run/netns/<name>).
    pub name: String,
    /// IP address for host side of veth.
    pub host_ip: Ipv4Addr,
    /// IP address for sandbox side of veth.
    pub sandbox_ip: Ipv4Addr,
    /// Subnet prefix length (typically 24 for /24).
    pub prefix_len: u8,
    /// Port for the proxy to listen on.
    pub proxy_port: u16,
    /// DNS servers for synthetic resolv.conf.
    ///
    /// **Important**: Do not use `127.0.0.53` (systemd-resolved) as it won't
    /// work inside the network namespace.
    pub dns_servers: Vec<Ipv4Addr>,
}

impl Default for NetnsConfig {
    fn default() -> Self {
        Self {
            name: format!("secure-llm-{}", std::process::id()),
            host_ip: Ipv4Addr::new(10, 200, 0, 1),
            sandbox_ip: Ipv4Addr::new(10, 200, 0, 2),
            prefix_len: 24,
            proxy_port: 8080,
            // Default to Google DNS; corporate deployments should override with internal DNS
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        }
    }
}

/// Handle to a created network namespace.
///
/// When dropped, the namespace and its associated resources are cleaned up.
pub struct NetworkNamespace {
    /// Path to the namespace file (/run/netns/<name>).
    pub path: PathBuf,
    /// Name of the namespace.
    pub name: String,
    /// Host-side veth interface name.
    pub host_veth: String,
    /// Sandbox-side veth interface name.
    pub sandbox_veth: String,
    /// Host IP address.
    pub host_ip: Ipv4Addr,
    /// Sandbox IP address.
    pub sandbox_ip: Ipv4Addr,
    /// Proxy address for sandbox to use.
    pub proxy_addr: String,
    /// Path to synthetic resolv.conf for bind-mounting.
    pub resolv_conf_path: PathBuf,
    /// Temp directory for network-related files.
    temp_dir: PathBuf,
    /// Whether to clean up on drop.
    cleanup_on_drop: bool,
}

impl NetworkNamespace {
    /// Create a new network namespace with veth pair.
    ///
    /// This sets up:
    /// 1. A new network namespace
    /// 2. A veth pair connecting host and sandbox
    /// 3. IP addresses on both ends
    /// 4. Routing in the sandbox
    /// 5. A synthetic resolv.conf with real DNS servers
    ///
    /// # Requirements
    ///
    /// - `CAP_NET_ADMIN` capability or root access
    /// - `ip` command available
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - `ip` commands fail (usually permissions)
    /// - Temp directory cannot be created
    /// - Namespace already exists
    pub fn create(config: NetnsConfig) -> Result<Self, NetnsError> {
        info!("Creating network namespace: {}", config.name);

        // Generate short interface names (max 15 chars for Linux)
        let ns_prefix = &config.name[..8.min(config.name.len())];
        let host_veth = format!("veth-{}-h", ns_prefix);
        let sandbox_veth = format!("veth-{}-s", ns_prefix);

        // Validate interface names
        if host_veth.len() > 15 {
            return Err(NetnsError::InterfaceNameTooLong { name: host_veth });
        }
        if sandbox_veth.len() > 15 {
            return Err(NetnsError::InterfaceNameTooLong { name: sandbox_veth });
        }

        // Create temp directory for network files
        let temp_dir = tempfile::Builder::new()
            .prefix("secure-llm-netns-")
            .tempdir()
            .map_err(NetnsError::TempDir)?
            .keep();

        debug!("Temp directory for network files: {:?}", temp_dir);

        // Create the network namespace
        run_ip(&["netns", "add", &config.name])?;

        // Create veth pair
        run_ip(&[
            "link",
            "add",
            &host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &sandbox_veth,
        ])?;

        // Move sandbox veth to the namespace
        run_ip(&["link", "set", &sandbox_veth, "netns", &config.name])?;

        // Configure host side
        let host_addr = format!("{}/{}", config.host_ip, config.prefix_len);
        run_ip(&["addr", "add", &host_addr, "dev", &host_veth])?;
        run_ip(&["link", "set", &host_veth, "up"])?;

        // Configure sandbox side (run in namespace)
        let sandbox_addr = format!("{}/{}", config.sandbox_ip, config.prefix_len);
        run_ip_netns(&config.name, &["addr", "add", &sandbox_addr, "dev", &sandbox_veth])?;
        run_ip_netns(&config.name, &["link", "set", &sandbox_veth, "up"])?;
        run_ip_netns(&config.name, &["link", "set", "lo", "up"])?;

        // Set default route to host in the sandbox
        run_ip_netns(
            &config.name,
            &["route", "add", "default", "via", &config.host_ip.to_string()],
        )?;

        // Enable IP forwarding on host
        if let Err(e) = enable_ip_forwarding() {
            warn!("Failed to enable IP forwarding: {}. Traffic may not route correctly.", e);
        }

        // Create synthetic resolv.conf with real DNS servers
        let resolv_conf_path = temp_dir.join("resolv.conf");
        let resolv_content = config
            .dns_servers
            .iter()
            .map(|ip| format!("nameserver {}", ip))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&resolv_conf_path, &resolv_content).map_err(NetnsError::ResolvConfWrite)?;

        debug!("Synthetic resolv.conf created at {:?}", resolv_conf_path);

        let proxy_addr = format!("http://{}:{}", config.host_ip, config.proxy_port);

        info!(
            "Network namespace {} created: host={}, sandbox={}, proxy={}",
            config.name, config.host_ip, config.sandbox_ip, proxy_addr
        );

        Ok(Self {
            path: PathBuf::from(format!("/run/netns/{}", config.name)),
            name: config.name,
            host_veth,
            sandbox_veth,
            host_ip: config.host_ip,
            sandbox_ip: config.sandbox_ip,
            proxy_addr,
            resolv_conf_path,
            temp_dir,
            cleanup_on_drop: true,
        })
    }

    /// Get the path to the namespace file (for bwrap --userns).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the proxy URL for HTTP_PROXY/HTTPS_PROXY env vars.
    pub fn proxy_url(&self) -> &str {
        &self.proxy_addr
    }

    /// Disable cleanup on drop (for debugging).
    pub fn persist(&mut self) {
        warn!("Network namespace persistence enabled - namespace will not be deleted on exit");
        self.cleanup_on_drop = false;
    }

    /// Clean up the namespace and associated resources.
    ///
    /// Called automatically on drop, but can be called explicitly.
    pub fn destroy(&self) -> Result<(), NetnsError> {
        debug!("Destroying network namespace: {}", self.name);

        // Delete namespace (this also removes the veth pair)
        if let Err(e) = run_ip(&["netns", "delete", &self.name]) {
            warn!("Failed to delete network namespace: {}", e);
        }

        // Clean up temp directory
        if let Err(e) = fs::remove_dir_all(&self.temp_dir) {
            warn!("Failed to remove temp directory: {}", e);
        }

        Ok(())
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        if self.cleanup_on_drop
            && let Err(e) = self.destroy()
        {
            warn!("Failed to clean up network namespace: {}", e);
        }
    }
}

/// Run an `ip` command.
fn run_ip(args: &[&str]) -> Result<(), NetnsError> {
    let cmd_str = format!("ip {}", args.join(" "));
    debug!("Running: {}", cmd_str);

    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| NetnsError::CommandFailed {
            cmd: cmd_str.clone(),
            source: e,
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(NetnsError::CommandError { cmd: cmd_str, stderr });
    }

    Ok(())
}

/// Run an `ip` command inside a network namespace.
fn run_ip_netns(ns: &str, args: &[&str]) -> Result<(), NetnsError> {
    let mut full_args = vec!["netns", "exec", ns, "ip"];
    full_args.extend(args);
    run_ip(&full_args)
}

/// Enable IP forwarding on the host.
fn enable_ip_forwarding() -> Result<(), NetnsError> {
    // Check current value first
    let current = fs::read_to_string("/proc/sys/net/ipv4/ip_forward").ok();
    if current.as_ref().map(|s| s.trim()) == Some("1") {
        debug!("IP forwarding already enabled");
        return Ok(());
    }

    debug!("Enabling IP forwarding");
    fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| NetnsError::SysctlFailed { source: e })
}

/// Check if a network namespace exists.
pub fn namespace_exists(name: &str) -> bool {
    Path::new(&format!("/run/netns/{}", name)).exists()
}

/// List all secure-llm network namespaces.
pub fn list_secure_llm_namespaces() -> Vec<String> {
    let netns_dir = Path::new("/run/netns");
    if !netns_dir.exists() {
        return Vec::new();
    }

    match fs::read_dir(netns_dir) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("secure-llm-") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NetnsConfig::default();

        assert!(config.name.starts_with("secure-llm-"));
        assert_eq!(config.host_ip, Ipv4Addr::new(10, 200, 0, 1));
        assert_eq!(config.sandbox_ip, Ipv4Addr::new(10, 200, 0, 2));
        assert_eq!(config.prefix_len, 24);
        assert_eq!(config.proxy_port, 8080);
        assert!(!config.dns_servers.is_empty());
    }

    #[test]
    fn test_custom_config() {
        let config = NetnsConfig {
            name: "test-ns".to_string(),
            host_ip: Ipv4Addr::new(192, 168, 100, 1),
            sandbox_ip: Ipv4Addr::new(192, 168, 100, 2),
            prefix_len: 28,
            proxy_port: 9090,
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
        };

        assert_eq!(config.name, "test-ns");
        assert_eq!(config.host_ip, Ipv4Addr::new(192, 168, 100, 1));
    }

    #[test]
    fn test_list_secure_llm_namespaces() {
        // This test doesn't require privileges - just checks the function works
        let _namespaces = list_secure_llm_namespaces();
        // We don't assert anything specific since we don't know what namespaces exist
    }

    #[test]
    fn test_namespace_exists() {
        // Test with a namespace that definitely doesn't exist
        assert!(!namespace_exists("definitely-does-not-exist-12345"));
    }

    // Integration tests that require CAP_NET_ADMIN
    #[test]
    #[ignore = "requires CAP_NET_ADMIN"]
    fn test_network_namespace_creation() {
        let config = NetnsConfig {
            name: "secure-llm-test-ns".to_string(),
            ..Default::default()
        };

        let netns = NetworkNamespace::create(config).unwrap();

        // Verify namespace exists
        assert!(netns.path().exists());

        // Verify resolv.conf was created
        assert!(netns.resolv_conf_path.exists());
        let resolv_content = fs::read_to_string(&netns.resolv_conf_path).unwrap();
        assert!(resolv_content.contains("nameserver"));

        // Drop should clean up
        drop(netns);

        // Verify namespace was deleted
        assert!(!namespace_exists("secure-llm-test-ns"));
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN"]
    fn test_network_namespace_connectivity() {
        let config = NetnsConfig {
            name: "secure-llm-test-conn".to_string(),
            ..Default::default()
        };

        let netns = NetworkNamespace::create(config).unwrap();

        // Test ping from sandbox to host
        let output = Command::new("ip")
            .args([
                "netns",
                "exec",
                &netns.name,
                "ping",
                "-c",
                "1",
                "-W",
                "1",
                &netns.host_ip.to_string(),
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "Sandbox should be able to ping host"
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN"]
    fn test_network_namespace_persist() {
        let name = "secure-llm-test-persist";
        let config = NetnsConfig {
            name: name.to_string(),
            ..Default::default()
        };

        let path;
        {
            let mut netns = NetworkNamespace::create(config).unwrap();
            netns.persist();
            path = netns.path.clone();
        }

        // Should still exist after drop
        assert!(path.exists());

        // Manual cleanup
        run_ip(&["netns", "delete", name]).unwrap();
    }
}
