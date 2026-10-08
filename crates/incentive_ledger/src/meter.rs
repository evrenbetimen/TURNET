//! Metering: raw uptime/throughput samples → billable units. **Stub.**

use crate::LedgerError;
use dht_resolver::NodeId;

/// A raw usage sample reported by a node.
#[derive(Debug, Clone, Copy)]
pub struct UsageSample {
    /// Which node produced the sample.
    pub node: NodeId,
    /// Seconds of uptime in this window.
    pub uptime_secs: u64,
    /// Bytes relayed in this window.
    pub bytes_relayed: u64,
}

/// Convert a sample into billable units.
///
/// Stub: the unit model (how uptime and bandwidth combine, anti-fraud
/// weighting) is a later milestone.
pub fn to_billable_units(_sample: &UsageSample) -> Result<u64, LedgerError> {
    Err(LedgerError::NotImplemented("metering unit model"))
}
