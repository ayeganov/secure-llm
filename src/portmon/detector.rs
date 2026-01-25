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
//! ```ignore
//! use secure_llm::portmon::detector::{PortDetector, PortEvent, PortState};
//! use std::time::Duration;
//! use tokio::sync::mpsc;
//!
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
//! ```

use super::error::PortMonError;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    /// PID of the sandbox process.
    ///
    /// **Critical**: We use PID, not netns name, because reading via
    /// `ip netns exec` requires root, but /proc/<pid>/net/* is readable
    /// by the user who spawned the process.
    sandbox_pid: u32,
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
    /// * `sandbox_pid` - PID of the sandbox process (e.g., bwrap's PID or a child process)
    /// * `poll_interval` - How often to scan for port changes
    pub fn new(sandbox_pid: u32, poll_interval: Duration) -> Self {
        Self {
            sandbox_pid,
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
    fn scan_ports(&self) -> Result<HashMap<u64, ListeningPort>, PortMonError> {
        let mut ports = HashMap::new();

        // Scan IPv4 listening ports
        let tcp4_path = format!("/proc/{}/net/tcp", self.sandbox_pid);
        if std::path::Path::new(&tcp4_path).exists() {
            match std::fs::read_to_string(&tcp4_path) {
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
        let tcp6_path = format!("/proc/{}/net/tcp6", self.sandbox_pid);
        if std::path::Path::new(&tcp6_path).exists() {
            match std::fs::read_to_string(&tcp6_path) {
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

    /// Get the sandbox PID being monitored.
    pub fn sandbox_pid(&self) -> u32 {
        self.sandbox_pid
    }

    /// Get the current known ports (for inspection).
    pub fn known_ports(&self) -> &HashMap<u64, ListeningPort> {
        &self.known_ports
    }
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
