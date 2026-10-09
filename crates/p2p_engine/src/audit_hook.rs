//! Consent-gated connection-record hook.
//!
//! This is the bridge between the relay handshake and the operator's local
//! audit log in [`compliance_reporting`]. Its design is intentionally narrow:
//!
//! - **Off by default.** [`AuditPolicy::default`] disables recording. An
//!   operator must explicitly opt in, which is a legal/policy decision for
//!   the person running the node, not a network default.
//! - **Disclosure required to record.** Recording only produces a record when
//!   the operator has set an [`AuditPolicy::operator_disclosure`]. There is no
//!   way to enable silent logging through this type: no disclosure, no record.
//! - **Local and first-party only.** It records what *this* node observed,
//!   into *this* node's store. There is no path here to collect, forward, or
//!   centralize other nodes' records.
//!
//! This is the opposite of a covert, network-wide tap. See the crate-level
//! docs of [`compliance_reporting`] for the full rationale and the
//! capabilities that were deliberately left out.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use compliance_reporting::ConnectionRecord;
use dht_resolver::NodeId;

/// Whether, and how, this node records the connections it handles.
#[derive(Debug, Clone, Default)]
pub struct AuditPolicy {
    /// Master switch. `false` means no connection records are written.
    pub enabled: bool,
    /// Human-readable note shown in the UI and included in exports stating the
    /// legal basis under which the operator enabled logging. **Required** for
    /// any record to be produced — this enforces that logging is disclosed.
    pub operator_disclosure: Option<String>,
}

impl AuditPolicy {
    /// An enabled policy carrying the operator's disclosure string. This is the
    /// only way to get a recording policy, so recording is always disclosed.
    pub fn enabled(operator_disclosure: impl Into<String>) -> Self {
        Self {
            enabled: true,
            operator_disclosure: Some(operator_disclosure.into()),
        }
    }

    /// Is this policy actually able to record (enabled *and* disclosed)?
    pub fn is_recording(&self) -> bool {
        self.enabled && self.operator_disclosure.is_some()
    }

    /// Build the audit record for an observed connection, or `None` when the
    /// policy is disabled or undisclosed. Returning `None` is the default path.
    pub fn record_for(&self, conn: &ObservedConnection) -> Option<ConnectionRecord> {
        if !self.is_recording() {
            return None;
        }
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as i128)
            .unwrap_or(0);
        Some(ConnectionRecord {
            node_id_hex: conn.peer.to_hex(),
            observed_addr: conn.peer_addr.to_string(),
            ts_unix_micros: ts,
            bytes: conn.bytes,
            session_key_id: conn.session_key_id.clone(),
        })
    }
}

/// What this node observed about one connection it handled.
#[derive(Debug, Clone)]
pub struct ObservedConnection {
    /// The peer's cryptographic node id.
    pub peer: NodeId,
    /// The peer's transport address as observed by this node.
    pub peer_addr: SocketAddr,
    /// Bytes relayed for this session.
    pub bytes: u64,
    /// Non-secret session key identifier (never the key itself).
    pub session_key_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> ObservedConnection {
        ObservedConnection {
            peer: NodeId(0xABCD),
            peer_addr: "198.51.100.7:51820".parse().unwrap(),
            bytes: 1420,
            session_key_id: "kid:9f2c".into(),
        }
    }

    #[test]
    fn default_policy_records_nothing() {
        assert!(AuditPolicy::default().record_for(&conn()).is_none());
    }

    #[test]
    fn enabled_without_disclosure_records_nothing() {
        let p = AuditPolicy {
            enabled: true,
            operator_disclosure: None,
        };
        assert!(p.record_for(&conn()).is_none());
    }

    #[test]
    fn disclosed_policy_produces_record() {
        let p = AuditPolicy::enabled("Retained under operator policy; disclosed to users.");
        let rec = p.record_for(&conn()).expect("should record");
        assert_eq!(rec.node_id_hex, "000000000000abcd");
        assert_eq!(rec.bytes, 1420);
    }
}
