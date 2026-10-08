//! # compliance_reporting — operator-local, consent-based audit tooling
//!
//! ## What this crate is
//! A node operator may be obliged to answer a lawful, targeted request about
//! connections *their own node* handled. This crate gives that operator the
//! tools to keep a local, tamper-evident audit log and to produce a signed
//! export from it under due process. Concretely:
//!
//! - [`ConnectionRecord`] — the record shape: the node-observed peer address,
//!   the 64-bit Node ID, a microsecond timestamp, and metadata (packet size,
//!   a key *identifier* — never key material).
//! - [`store`] — a local SQLite store (`rusqlite`, WAL mode).
//! - [`exporter`] — a signed JSON / CSV exporter for review under process.
//! - [`node_control`] — a **local** operator-controlled pause/shutdown
//!   primitive for the operator's own node.
//! - [`honeypot`] — a documented stub (see below).
//!
//! ## What this crate is NOT — deliberate design boundaries
//! These boundaries are intentional. They are called out so a future
//! contributor does not "complete" them by accident.
//!
//! 1. **Not a network-wide tap.** Every record is first-party: it describes
//!    only what the local node observed, stored locally. There is no
//!    collection, forwarding, or centralization of other nodes' data here,
//!    and nothing that correlates users across the whole network.
//! 2. **Not covert.** Logging is opt-in at the node
//!    ([`p2p_engine::audit_hook::AuditPolicy`] is off by default) and is meant
//!    to be disclosed to users so they can choose relays accordingly.
//! 3. **No network-region freeze "kill-switch."** The original concept of a
//!    genesis-key signal that freezes whole network regions has been
//!    **intentionally omitted**. Region-scale, externally-triggered shutdown
//!    is censorship infrastructure, not operator compliance tooling.
//!    [`node_control`] offers only a *local* pause/stop for the operator's own
//!    node. If a different scope is ever genuinely required, it must be
//!    designed deliberately, with its own review — not grown from this stub.
//! 4. **Keys are never logged.** Records carry a key *identifier* for
//!    correlation, never session key material.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod exporter;
pub mod honeypot;
pub mod node_control;
pub mod store;

/// Errors from the audit/compliance subsystem.
#[derive(Debug, Error)]
pub enum ComplianceError {
    #[error("not implemented in scaffold: {0}")]
    NotImplemented(&'static str),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("export error: {0}")]
    Export(String),
    #[error("invalid node state transition: {0}")]
    InvalidTransition(&'static str),
}

/// One first-party connection record held by a node operator.
///
/// This is what the local node observed about a connection *it* handled. It
/// is not derived from, nor shared with, any other node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    /// 64-bit cryptographic Node ID of the peer, hex-encoded.
    pub node_id_hex: String,
    /// The peer's transport address as observed by this node.
    pub observed_addr: String,
    /// Microsecond Unix timestamp of the observation.
    pub ts_unix_micros: i128,
    /// Total bytes in the observed packet/session, for throughput accounting.
    pub bytes: u64,
    /// A non-secret identifier for the session key (e.g. a hash prefix).
    /// **Never** the key itself.
    pub session_key_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_serializes() {
        let r = ConnectionRecord {
            node_id_hex: "000000000000abcd".into(),
            observed_addr: "198.51.100.7:51820".into(),
            ts_unix_micros: 1_700_000_000_000_000,
            bytes: 1420,
            session_key_id: "kid:9f2c".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("000000000000abcd"));
    }
}
