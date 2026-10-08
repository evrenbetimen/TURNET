//! Intrusion-tracking honeypot. **Documented stub only.**
//!
//! A defensive honeypot is an isolated, decoy service used to detect and
//! study unauthorized intrusion attempts against the operator's own
//! infrastructure. In Turnet this is scoped as a *defensive* tool for a node
//! operator to flag malicious traffic hitting their node.
//!
//! It is left as an inert documented stub in this scaffold. Nothing here
//! deploys a decoy, captures traffic, or flags anyone; the type exists to
//! mark where a reviewed defensive implementation would attach. Any real
//! implementation must stay isolated from production relay traffic and must
//! not become a tool for offensive tracking of ordinary users.

use crate::ComplianceError;

/// A flagged intrusion observation (shape only).
pub struct IntrusionFlag {
    /// Short description of the observed probe.
    pub summary: String,
}

/// A defensive honeypot sensor. Inert in the scaffold.
pub struct Honeypot;

impl Honeypot {
    /// Poll for newly observed intrusion attempts.
    ///
    /// Stub: always returns [`ComplianceError::NotImplemented`].
    pub fn poll(&self) -> Result<Vec<IntrusionFlag>, ComplianceError> {
        Err(ComplianceError::NotImplemented("defensive honeypot sensor"))
    }
}
