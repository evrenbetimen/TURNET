//! Consent-gated connection-record hook.
//!
//! This is the bridge between the relay handshake and the operator's local
//! audit log in [`compliance_reporting`]. Its design is intentionally narrow:
//!
//! - **Off by default.** [`AuditPolicy::default`] disables recording. An
//!   operator must explicitly opt in, which is a legal/policy decision for
//!   the person running the node, not a network default.
//! - **Local and first-party only.** It records what *this* node observed,
//!   into *this* node's store. There is no path here to collect, forward, or
//!   centralize other nodes' records.
//! - **Transparent.** Because the policy is explicit and local, an operator
//!   can disclose to users that a given entry relay keeps connection logs, so
//!   users can make an informed choice of relay.
//!
//! This is the opposite of a covert, network-wide tap. See the crate-level
//! docs of [`compliance_reporting`] for the full rationale and the
//! capabilities that were deliberately left out.

use crate::handshake::Session;
use compliance_reporting::ConnectionRecord;

/// Whether, and how, this node records the connections it handles.
#[derive(Debug, Clone)]
pub struct AuditPolicy {
    /// Master switch. `false` means no connection records are written.
    pub enabled: bool,
    /// Human-readable note shown in the UI and included in exports stating
    /// the legal basis under which the operator enabled logging.
    pub operator_disclosure: Option<String>,
}

impl Default for AuditPolicy {
    /// Recording is **off** by default.
    fn default() -> Self {
        Self {
            enabled: false,
            operator_disclosure: None,
        }
    }
}

impl AuditPolicy {
    /// Build the audit record for a session, or `None` when recording is
    /// disabled. Returning `None` is the default path.
    ///
    /// Scaffold: shapes the record from the session but does not persist it;
    /// persistence is [`compliance_reporting`]'s job and is itself stubbed.
    pub fn record_for(&self, _session: &Session) -> Option<ConnectionRecord> {
        if !self.enabled {
            return None;
        }
        // A real build would populate a ConnectionRecord from the session and
        // hand it to the local store. Left unpopulated in the scaffold.
        None
    }
}
