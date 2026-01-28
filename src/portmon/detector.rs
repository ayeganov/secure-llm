//! Port detection for sandbox listening ports.
//!
//! This module monitors for new listening ports inside the sandbox by polling
//! `/proc/<sandbox_pid>/net/tcp` and `/proc/<sandbox_pid>/net/tcp6`.
//!
//! # Critical Implementation Notes
//!
//! 1. **The `ip netns exec` Trap**: The naive approach is `ip netns exec <name> cat /proc/net/tcp`.
//!    **This requires root/CAP_SYS_ADMIN!** Since `secure-llm` runs as a normal user with
//!    unprivileged namespaces, this will fail with "Permission denied".
//!
//!    **The Fix**: Read directly from `/proc/<sandbox_pid>/net/tcp`. Since `secure-llm` spawned
//!    the sandbox process, we can read the child's proc entries without special privileges.
//!
//! 2. **The IPv6 Blind Spot**: Modern tools (Node.js, Next.js, Vite, Python's http.server) often
//!    bind to `::` (IPv6 any) by default. If you only scan `/proc/<pid>/net/tcp`, you'll miss
//!    these ports entirely.
//!
//!    **The Fix**: Scan BOTH `/proc/<pid>/net/tcp` AND `/proc/<pid>/net/tcp6`.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() {
//! use secure_llm::portmon::detector::{PortDetector, PortEvent, PortState};
//! use std::time::Duration;
//! use tokio::sync::mpsc;
//!
//! let sandbox_pid = std::process::id(); // In practice, this is the sandbox PID
//! let detector = PortDetector::new(sandbox_pid, Duration::from_secs(2));
//! let (tx, mut rx) = mpsc::channel(32);
//! let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
//!
//! tokio::spawn(detector.run(tx, shutdown_rx));
//!
//! while let Some(event) = rx.recv().await {
//!     match event.state {
//!         PortState::New => println!("New port: {}", event.port.port),
//!         PortState::Closed => println!("Port closed: {}", event.port.port),
//!         _ => {}
//!     }
//! }
//! # }
//! ```

use super::error::PortMonError;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tracing::{debug, trace};

/// Information about a listening port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListeningPort {
    /// The port number.
    pub port: u16,
    /// Local address (0.0.0.0, 127.0.0.1, ::, ::1, etc.).
    pub local_addr: IpAddr,
    /// Process name if identifiable.
    pub process_name: Option<String>,
    /// Socket inode number (unique identifier).
    pub inode: u64,
    /// Whether this is an IPv6 socket.
    pub is_ipv6: bool,
}

/// State of a detected port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Port is newly listening.
    New,
    /// Port is still listening (previously seen).
    Existing,
    /// Port stopped listening.
    Closed,
}

/// Event from the port detector.
#[derive(Debug, Clone)]
pub struct PortEvent {
    /// The port that changed state.
    pub port: ListeningPort,
    /// The new state.
    pub state: PortState,
}

/// Port detector that monitors for new listening ports.
///
/// Scans `/proc/<pid>/net/tcp` and `/proc/<pid>/net/tcp6` for listening sockets.
pub struct PortDetector {
    /// PID of the sandbox wrapper process (e.g., bwrap).
    wrapper_pid: u32,
    /// PID of a process actually inside the sandbox network namespace.
    /// This is resolved lazily because child processes may not exist immediately.
    namespace_pid: Option<u32>,
    /// Previously seen ports (by inode to handle port reuse).
    known_ports: HashMap<u64, ListeningPort>,
    /// Polling interval.
    poll_interval: Duration,
}

impl PortDetector {
    /// Create a new port detector for a sandbox process.
    ///
    /// # Arguments
    ///
    /// * `sandbox_pid` - PID of the sandbox wrapper process (e.g., bwrap's PID)
    /// * `poll_interval` - How often to scan for port changes
    ///
    /// # Note
    ///
    /// The detector will automatically find a child process that's inside the
    /// sandbox's network namespace, since bwrap itself may stay in the host namespace.
    pub fn new(sandbox_pid: u32, poll_interval: Duration) -> Self {
        Self {
            wrapper_pid: sandbox_pid,
            namespace_pid: None,
            known_ports: HashMap::new(),
            poll_interval,
        }
    }

    /// Start the detection loop, sending events to the provided channel.
    ///
    /// Runs until the shutdown signal is received or the channel is closed.
    pub async fn run(
        mut self,
        event_tx: mpsc::Sender<PortEvent>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let mut interval = tokio::time::interval(self.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.poll_once() {
                        Ok(events) => {
                            for event in events {
                                if event_tx.send(event).await.is_err() {
                                    // Receiver dropped, shut down
                                    debug!("Port detector receiver dropped, shutting down");
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            // Log but continue - process might have exited
                            trace!("Port detection error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("Port detector received shutdown signal");
                        break;
                    }
                }
            }
        }
    }

    /// Poll once for port changes.
    ///
    /// Returns a list of port events (new ports, closed ports).
    pub fn poll_once(&mut self) -> Result<Vec<PortEvent>, PortMonError> {
        let current_ports = self.scan_ports()?;
        let mut events = Vec::new();

        // Find new ports
        for (inode, port) in &current_ports {
            if !self.known_ports.contains_key(inode) {
                debug!(
                    "New listening port detected: {} on {:?}",
                    port.port, port.local_addr
                );
                events.push(PortEvent {
                    port: port.clone(),
                    state: PortState::New,
                });
            }
        }

        // Find closed ports
        for (inode, port) in &self.known_ports {
            if !current_ports.contains_key(inode) {
                debug!("Port closed: {} on {:?}", port.port, port.local_addr);
                events.push(PortEvent {
                    port: port.clone(),
                    state: PortState::Closed,
                });
            }
        }

        // Update known ports
        self.known_ports = current_ports;

        Ok(events)
    }

    /// Scan for currently listening ports in the sandbox namespace.
    ///
    /// Reads directly from /proc/<pid>/net/tcp and /proc/<pid>/net/tcp6.
    /// This does NOT require root - we can read the proc files of processes we spawned.
    fn scan_ports(&mut self) -> Result<HashMap<u64, ListeningPort>, PortMonError> {
        // Ensure we have the correct PID for the namespace
        let pid = self.get_namespace_pid();

        let mut ports = HashMap::new();

        // Scan IPv4 listening ports
        let tcp4_path = format!("/proc/{}/net/tcp", pid);
        if Path::new(&tcp4_path).exists() {
            match fs::read_to_string(&tcp4_path) {
                Ok(content) => {
                    let ipv4_ports = parse_proc_net_tcp(&content, false)?;
                    ports.extend(ipv4_ports);
                }
                Err(e) => {
                    // Process might have exited - don't fail hard
                    trace!("Could not read {}: {}", tcp4_path, e);
                }
            }
        }

        // Scan IPv6 listening ports (CRITICAL: many modern tools bind to :: by default)
        let tcp6_path = format!("/proc/{}/net/tcp6", pid);
        if Path::new(&tcp6_path).exists() {
            match fs::read_to_string(&tcp6_path) {
                Ok(content) => {
                    let ipv6_ports = parse_proc_net_tcp(&content, true)?;
                    ports.extend(ipv6_ports);
                }
                Err(e) => {
                    trace!("Could not read {}: {}", tcp6_path, e);
                }
            }
        }

        Ok(ports)
    }

    /// Get a PID that's inside the sandbox's network namespace.
    ///
    /// bwrap itself may stay in the host namespace, so we need to find a child
    /// process that's actually inside the sandbox's network namespace.
    fn get_namespace_pid(&mut self) -> u32 {
        // Return cached PID if we have one and it still exists
        if let Some(pid) = self.namespace_pid {
            if Path::new(&format!("/proc/{}", pid)).exists() {
                return pid;
            }
            // PID no longer exists, need to find a new one
            self.namespace_pid = None;
        }

        // Try to find a child process in a different network namespace
        if let Some(child_pid) = find_child_in_different_netns(self.wrapper_pid) {
            debug!(
                "Found child PID {} in sandbox network namespace (wrapper PID: {})",
                child_pid, self.wrapper_pid
            );
            self.namespace_pid = Some(child_pid);
            return child_pid;
        }

        // Fallback to wrapper PID (might not work for network detection)
        trace!(
            "No child in different netns found, using wrapper PID {}",
            self.wrapper_pid
        );
        self.wrapper_pid
    }

    /// Get the wrapper PID being monitored.
    pub fn sandbox_pid(&self) -> u32 {
        self.wrapper_pid
    }

    /// Get the current known ports (for inspection).
    pub fn known_ports(&self) -> &HashMap<u64, ListeningPort> {
        &self.known_ports
    }
}

/// Find a child process of the given PID that's in a different network namespace.
///
/// This is needed because bwrap (the sandbox wrapper) may stay in the host network
/// namespace while only putting its child processes into the sandbox namespace.
///
/// Returns the PID of the first child found in a different namespace, or None.
fn find_child_in_different_netns(parent_pid: u32) -> Option<u32> {
    // Get the parent's network namespace
    let parent_netns = fs::read_link(format!("/proc/{}/ns/net", parent_pid)).ok()?;

    // Find all child processes by scanning /proc
    let proc_dir = fs::read_dir("/proc").ok()?;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip non-numeric entries
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Skip the parent itself
        if pid == parent_pid {
            continue;
        }

        // Check if this process is a descendant of the parent
        let ppid_path = format!("/proc/{}/stat", pid);
        if let Ok(stat_content) = fs::read_to_string(&ppid_path)
            && let Some(pos) = stat_content.rfind(')')
        {
            // Format: pid (comm) state ppid ...
            // The comm field can contain spaces and parentheses, so we need to find
            // the last ')' and parse from there
            let after_comm = &stat_content[pos + 1..];
            let fields: Vec<&str> = after_comm.split_whitespace().collect();
            if fields.len() >= 2
                && let Ok(ppid) = fields[1].parse::<u32>()
                // Check if this is a direct child or descendant of parent
                && (ppid == parent_pid || is_descendant_of(pid, parent_pid))
                // Check if it's in a different network namespace
                && let Ok(child_netns) = fs::read_link(format!("/proc/{}/ns/net", pid))
                && child_netns != parent_netns
            {
                return Some(pid);
            }
        }
    }

    None
}

/// Check if a process is a descendant of a given ancestor.
fn is_descendant_of(pid: u32, ancestor: u32) -> bool {
    let mut current = pid;
    let mut depth = 0;
    const MAX_DEPTH: u32 = 20; // Prevent infinite loops

    while depth < MAX_DEPTH {
        let stat_path = format!("/proc/{}/stat", current);
        if let Ok(content) = fs::read_to_string(&stat_path)
            && let Some(pos) = content.rfind(')')
        {
            let after_comm = &content[pos + 1..];
            let fields: Vec<&str> = after_comm.split_whitespace().collect();
            if fields.len() >= 2
                && let Ok(ppid) = fields[1].parse::<u32>()
            {
                if ppid == ancestor {
                    return true;
                }
                if ppid == 0 || ppid == 1 {
                    return false; // Reached init
                }
                current = ppid;
                depth += 1;
                continue;
            }
        }
        return false;
    }
    false
}

/// Parse /proc/net/tcp or /proc/net/tcp6 content.
///
/// Format (each line after header):
/// ```text
///    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
///    0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 ...
/// ```
///
/// For tcp6, the address is 128-bit (32 hex chars) instead of 32-bit (8 hex chars).
///
/// # Arguments
///
/// * `content` - Contents of /proc/net/tcp or /proc/net/tcp6
/// * `is_ipv6` - true if parsing tcp6, false for tcp
fn parse_proc_net_tcp(
    content: &str,
    is_ipv6: bool,
) -> Result<HashMap<u64, ListeningPort>, PortMonError> {
    let mut ports = HashMap::new();

    for line in content.lines().skip(1) {
        // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        // Parse local address (parts[1])
        let local = parts[1];
        let (addr, port) = if is_ipv6 {
            parse_hex_addr_v6(local)?
        } else {
            let (v4_addr, port) = parse_hex_addr_v4(local)?;
            (IpAddr::V4(v4_addr), port)
        };

        // Parse state (parts[3]) - 0A = LISTEN
        let state = u8::from_str_radix(parts[3], 16)
            .map_err(|_| PortMonError::ParseError(format!("Invalid state: {}", parts[3])))?;

        if state != 0x0A {
            // Not listening, skip
            continue;
        }

        // Parse inode (parts[9])
        let inode: u64 = parts[9]
            .parse()
            .map_err(|_| PortMonError::ParseError(format!("Invalid inode: {}", parts[9])))?;

        ports.insert(
            inode,
            ListeningPort {
                port,
                local_addr: addr,
                process_name: None, // Could be resolved via /proc/<pid>/fd
                inode,
                is_ipv6,
            },
        );
    }

    Ok(ports)
}

/// Parse hex-encoded IPv4 address:port (e.g., "00000000:1F90").
///
/// The address is stored in little-endian format in /proc/net/tcp.
/// For example, "0100007F:1F90" represents 127.0.0.1:8080
/// The hex bytes are: 01 00 00 7F, which in little-endian is 0x7F000001 = 127.0.0.1
fn parse_hex_addr_v4(s: &str) -> Result<(Ipv4Addr, u16), PortMonError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(PortMonError::ParseError(format!(
            "Invalid IPv4 address format: {}",
            s
        )));
    }

    // Address is stored in host byte order (little-endian on x86)
    // The hex string represents bytes in memory order, so we parse as big-endian
    // then swap to get the actual IP address
    let addr_hex = u32::from_str_radix(parts[0], 16)
        .map_err(|_| PortMonError::ParseError(format!("Invalid IPv4 address: {}", parts[0])))?;
    // swap_bytes converts from the stored format to network byte order
    let addr = Ipv4Addr::from(addr_hex.swap_bytes());

    // Port is in big-endian hex (network byte order)
    let port = u16::from_str_radix(parts[1], 16)
        .map_err(|_| PortMonError::ParseError(format!("Invalid port: {}", parts[1])))?;

    Ok((addr, port))
}

/// Parse hex-encoded IPv6 address:port (e.g., "00000000000000000000000000000000:1F90").
///
/// The address is stored as 4 little-endian 32-bit words in /proc/net/tcp6.
fn parse_hex_addr_v6(s: &str) -> Result<(IpAddr, u16), PortMonError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(PortMonError::ParseError(format!(
            "Invalid IPv6 address format: {}",
            s
        )));
    }

    // Address is 32 hex chars (128 bits), stored as 4 little-endian 32-bit words
    let addr_hex = parts[0];
    if addr_hex.len() != 32 {
        return Err(PortMonError::ParseError(format!(
            "Invalid IPv6 address length: expected 32 hex chars, got {}",
            addr_hex.len()
        )));
    }

    // Parse as 4 u32 words, each little-endian
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word_hex = &addr_hex[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(word_hex, 16)
            .map_err(|_| PortMonError::ParseError(format!("Invalid IPv6 word: {}", word_hex)))?;
        let word_le = word.to_le();
        let word_bytes = word_le.to_ne_bytes();
        octets[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }

    let addr = Ipv6Addr::from(octets);

    // Port is in big-endian hex
    let port = u16::from_str_radix(parts[1], 16)
        .map_err(|_| PortMonError::ParseError(format!("Invalid port: {}", parts[1])))?;

    Ok((IpAddr::V6(addr), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_addr_v4_localhost() {
        // 0100007F:1F90 = 127.0.0.1:8080
        let (addr, port) = parse_hex_addr_v4("0100007F:1F90").unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_hex_addr_v4_any() {
        // 00000000:0050 = 0.0.0.0:80
        let (addr, port) = parse_hex_addr_v4("00000000:0050").unwrap();
        assert_eq!(addr, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_hex_addr_v6_unspecified() {
        // :: (all zeros) on port 8080
        let (addr, port) =
            parse_hex_addr_v6("00000000000000000000000000000000:1F90").unwrap();
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_hex_addr_v6_loopback() {
        // ::1 (loopback) on port 80
        // IPv6 in /proc/net/tcp6 is stored as 4 little-endian 32-bit words
        let (addr, port) =
            parse_hex_addr_v6("00000000000000000000000001000000:0050").unwrap();
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_proc_net_tcp_v4() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1F90 0100007F:1234 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 100 0 0 10 0"#;

        let ports = parse_proc_net_tcp(content, false).unwrap();

        // Should find 2 listening ports (state 0A), not the established connection (state 01)
        assert_eq!(ports.len(), 2);

        // Check port 80 (0x50)
        let port_80 = ports.values().find(|p| p.port == 80).unwrap();
        assert_eq!(port_80.local_addr, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!port_80.is_ipv6);

        // Check port 8080 (0x1F90)
        let port_8080 = ports.values().find(|p| p.port == 8080).unwrap();
        assert_eq!(
            port_8080.local_addr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert!(!port_8080.is_ipv6);
    }

    #[test]
    fn test_parse_proc_net_tcp_v6() {
        let content = r#"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 100 0 0 10 0"#;

        let ports = parse_proc_net_tcp(content, true).unwrap();

        // Should find 1 listening port on ::
        assert_eq!(ports.len(), 1);

        let port = ports.values().next().unwrap();
        assert_eq!(port.port, 8080);
        assert_eq!(port.local_addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert!(port.is_ipv6);
    }

    #[test]
    fn test_port_detector_creation() {
        let detector = PortDetector::new(12345, Duration::from_secs(2));
        assert_eq!(detector.sandbox_pid(), 12345);
        assert!(detector.known_ports().is_empty());
    }

    #[test]
    fn test_invalid_address_format() {
        // Missing port separator
        assert!(parse_hex_addr_v4("00000000").is_err());
        assert!(parse_hex_addr_v6("00000000000000000000000000000000").is_err());
    }

    #[test]
    fn test_invalid_hex() {
        // Invalid hex in address
        assert!(parse_hex_addr_v4("GGGGGGGG:0050").is_err());
        // Invalid hex in port
        assert!(parse_hex_addr_v4("00000000:GGGG").is_err());
    }

    #[test]
    fn test_listening_port_equality() {
        let port1 = ListeningPort {
            port: 8080,
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            process_name: None,
            inode: 12345,
            is_ipv6: false,
        };

        let port2 = ListeningPort {
            port: 8080,
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            process_name: None,
            inode: 12345,
            is_ipv6: false,
        };

        assert_eq!(port1, port2);
    }
}
