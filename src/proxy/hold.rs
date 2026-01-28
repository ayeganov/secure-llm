//! Connection hold/resume for domains requiring user prompts.
//!
//! When a sandboxed tool tries to access an unknown domain, we need to:
//! 1. Pause (hold) the connection
//! 2. Prompt the user via IPC (implemented in Phase 4)
//! 3. Resume with allow, or drop with deny
//!
//! In Phase 3, we implement the infrastructure for holding connections.
//! The actual user prompting via IPC comes in Phase 4. For now, headless
//! mode blocks unknown domains immediately (fail-closed).
//!
//! # Timeout Handling
//!
//! Connections have a configurable timeout. If no decision is received
//! within the timeout, the connection is blocked (fail-closed).
//!
//! # Example
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use secure_llm::proxy::hold::{ConnectionHoldManager, ConnectionDecision};
//! use std::time::Duration;
//!
//! let manager = ConnectionHoldManager::new(Duration::from_secs(30));
//!
//! // Park a connection
//! let (id, decision_rx) = manager.park("api.unknown.com".into(), 443);
//!
//! // Later, record a decision (e.g., from TUI)
//! manager.decide(id, ConnectionDecision::Allow)?;
//!
//! // The parked connection receives the decision via the channel
//! let decision = decision_rx.await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{debug, info};
use uuid::Uuid;

/// Decision for a pending connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDecision {
    /// Allow the connection to proceed.
    Allow,
    /// Block the connection.
    Block,
}

/// A pending connection awaiting user decision.
struct PendingConnection {
    /// Unique identifier for this connection.
    id: Uuid,
    /// Target domain.
    domain: String,
    /// Target port.
    port: u16,
    /// When this connection was parked.
    parked_at: Instant,
    /// Channel to send the decision.
    decision_tx: oneshot::Sender<ConnectionDecision>,
}

/// Information about a pending connection (for TUI display).
#[derive(Debug, Clone)]
pub struct PendingInfo {
    /// Unique identifier.
    pub id: Uuid,
    /// Target domain.
    pub domain: String,
    /// Target port.
    pub port: u16,
    /// Seconds waiting for decision.
    pub waiting_secs: u64,
}

/// Manager for pending connections awaiting user decisions.
///
/// This manager tracks connections that are waiting for a user decision
/// and handles timeout enforcement.
pub struct ConnectionHoldManager {
    /// Pending connections by ID.
    pending: Mutex<HashMap<Uuid, PendingConnection>>,
    /// Timeout for pending connections.
    timeout: Duration,
}

impl ConnectionHoldManager {
    /// Create a new connection hold manager.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for a user decision.
    ///   After timeout, the connection is blocked (fail-closed).
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    /// Park a connection pending user decision.
    ///
    /// Returns the unique ID for this pending connection and a receiver
    /// that will receive the decision when made.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain being accessed.
    /// * `port` - The port being accessed.
    pub fn park(&self, domain: String, port: u16) -> (Uuid, oneshot::Receiver<ConnectionDecision>) {
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();

        let pending = PendingConnection {
            id,
            domain: domain.clone(),
            port,
            parked_at: Instant::now(),
            decision_tx: tx,
        };

        self.pending.lock().unwrap().insert(id, pending);

        debug!("Parked connection {} for {}:{}", id, domain, port);

        (id, rx)
    }

    /// Record a decision for a pending connection.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the pending connection.
    /// * `decision` - The decision (Allow or Block).
    ///
    /// # Errors
    ///
    /// Returns error if the connection is not found or was already closed.
    pub fn decide(&self, id: Uuid, decision: ConnectionDecision) -> Result<(), HoldError> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .remove(&id)
            .ok_or(HoldError::NotFound(id))?;

        debug!("Decision for {} ({}): {:?}", id, pending.domain, decision);

        pending
            .decision_tx
            .send(decision)
            .map_err(|_| HoldError::ConnectionClosed(id))
    }

    /// Get list of pending connections (for TUI display).
    pub fn list_pending(&self) -> Vec<PendingInfo> {
        self.pending
            .lock()
            .unwrap()
            .values()
            .map(|p| PendingInfo {
                id: p.id,
                domain: p.domain.clone(),
                port: p.port,
                waiting_secs: p.parked_at.elapsed().as_secs(),
            })
            .collect()
    }

    /// Get the number of pending connections.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Clean up timed-out connections.
    ///
    /// This should be called periodically (e.g., every second).
    /// Returns the list of domains that timed out (for logging).
    ///
    /// Timed-out connections are automatically blocked (fail-closed).
    pub fn cleanup_timeouts(&self) -> Vec<(String, u16)> {
        let mut timed_out = Vec::new();
        let mut pending = self.pending.lock().unwrap();

        // First, collect IDs of timed-out connections
        let timed_out_ids: Vec<Uuid> = pending
            .iter()
            .filter_map(|(id, conn)| {
                if conn.parked_at.elapsed() > self.timeout {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        // Then remove them and send block decisions
        for id in timed_out_ids {
            if let Some(conn) = pending.remove(&id) {
                info!(
                    "Connection {} for {}:{} timed out (fail-closed)",
                    conn.id, conn.domain, conn.port
                );
                timed_out.push((conn.domain.clone(), conn.port));

                // Send block decision (will fail if receiver dropped, which is fine)
                // We explicitly don't care about the error here
                let _ = conn.decision_tx.send(ConnectionDecision::Block);
            }
        }

        timed_out
    }

    /// Cancel a pending connection (e.g., if the client disconnected).
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the pending connection to cancel.
    ///
    /// Returns true if the connection was found and cancelled.
    pub fn cancel(&self, id: Uuid) -> bool {
        let removed = self.pending.lock().unwrap().remove(&id);
        if removed.is_some() {
            debug!("Cancelled pending connection {}", id);
            true
        } else {
            false
        }
    }

    /// Get the configured timeout duration.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Errors from connection hold operations.
#[derive(Debug, Error)]
pub enum HoldError {
    /// Pending connection was not found.
    #[error("Pending connection {0} not found")]
    NotFound(Uuid),

    /// Connection was closed while waiting for decision.
    #[error("Connection {0} was closed while waiting")]
    ConnectionClosed(Uuid),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_park_and_decide_allow() {
        let manager = ConnectionHoldManager::new(Duration::from_secs(30));

        let (id, rx) = manager.park("example.com".into(), 443);
        assert_eq!(manager.pending_count(), 1);

        manager.decide(id, ConnectionDecision::Allow).unwrap();

        let decision = rx.await.unwrap();
        assert_eq!(decision, ConnectionDecision::Allow);
        assert_eq!(manager.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_park_and_decide_block() {
        let manager = ConnectionHoldManager::new(Duration::from_secs(30));

        let (id, rx) = manager.park("evil.com".into(), 443);

        manager.decide(id, ConnectionDecision::Block).unwrap();

        let decision = rx.await.unwrap();
        assert_eq!(decision, ConnectionDecision::Block);
    }

    #[test]
    fn test_list_pending() {
        let manager = ConnectionHoldManager::new(Duration::from_secs(30));

        let (_id1, _rx1) = manager.park("example1.com".into(), 443);
        let (_id2, _rx2) = manager.park("example2.com".into(), 8080);

        let pending = manager.list_pending();
        assert_eq!(pending.len(), 2);

        let domains: Vec<&str> = pending.iter().map(|p| p.domain.as_str()).collect();
        assert!(domains.contains(&"example1.com"));
        assert!(domains.contains(&"example2.com"));
    }

    #[test]
    fn test_decide_not_found() {
        let manager = ConnectionHoldManager::new(Duration::from_secs(30));

        let result = manager.decide(Uuid::new_v4(), ConnectionDecision::Allow);
        assert!(matches!(result, Err(HoldError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_cleanup_timeouts() {
        // Very short timeout for testing
        let manager = ConnectionHoldManager::new(Duration::from_millis(10));

        let (_id, rx) = manager.park("slow.com".into(), 443);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(50)).await;

        let timed_out = manager.cleanup_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].0, "slow.com");
        assert_eq!(timed_out[0].1, 443);

        // Connection should receive Block
        let decision = rx.await.unwrap();
        assert_eq!(decision, ConnectionDecision::Block);

        // Should be removed from pending
        assert_eq!(manager.pending_count(), 0);
    }

    #[test]
    fn test_cancel() {
        let manager = ConnectionHoldManager::new(Duration::from_secs(30));

        let (id, _rx) = manager.park("example.com".into(), 443);
        assert_eq!(manager.pending_count(), 1);

        assert!(manager.cancel(id));
        assert_eq!(manager.pending_count(), 0);

        // Can't cancel again
        assert!(!manager.cancel(id));
    }

    #[test]
    fn test_pending_info_waiting_time() {
        let manager = ConnectionHoldManager::new(Duration::from_secs(30));

        let (_id, _rx) = manager.park("example.com".into(), 443);

        // Immediately after parking, waiting time should be 0
        let pending = manager.list_pending();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].waiting_secs <= 1);
    }

    #[test]
    fn test_multiple_connections_same_domain() {
        let manager = ConnectionHoldManager::new(Duration::from_secs(30));

        let (id1, _rx1) = manager.park("example.com".into(), 443);
        let (id2, _rx2) = manager.park("example.com".into(), 8080);

        assert_ne!(id1, id2);
        assert_eq!(manager.pending_count(), 2);
    }
}
