//! Metering: raw uptime/throughput samples → billable units.
//!
//! The unit model here is a simple, documented linear combination of the two
//! things a relay contributes: time spent available and bytes actually
//! relayed. It is deliberately deterministic integer arithmetic (no floats),
//! so every node computes the same units for the same sample over the long
//! lifecycle. Anti-fraud weighting (e.g. discounting self-reported uptime that
//! no peer corroborates) is a later milestone layered on top of this base
//! model, not a change to it.

use crate::LedgerError;
use dht_resolver::NodeId;

/// Seconds of availability that earn one uptime unit (one minute).
pub const SECS_PER_UPTIME_UNIT: u64 = 60;

/// Bytes relayed that earn one bandwidth unit (one mebibyte).
pub const BYTES_PER_BANDWIDTH_UNIT: u64 = 1024 * 1024;

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
/// `units = floor(uptime_secs / 60) + floor(bytes_relayed / 1 MiB)`, computed
/// with saturating integer arithmetic so an extreme sample clamps at
/// [`u64::MAX`] rather than overflowing. Sub-threshold remainders (under a
/// minute of uptime, under a mebibyte relayed) earn nothing this window; this
/// is intentional, so that a flood of tiny samples cannot be rounded up into
/// free credit.
pub fn to_billable_units(sample: &UsageSample) -> Result<u64, LedgerError> {
    let uptime_units = sample.uptime_secs / SECS_PER_UPTIME_UNIT;
    let bandwidth_units = sample.bytes_relayed / BYTES_PER_BANDWIDTH_UNIT;
    Ok(uptime_units.saturating_add(bandwidth_units))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(uptime_secs: u64, bytes_relayed: u64) -> UsageSample {
        UsageSample {
            node: NodeId(1),
            uptime_secs,
            bytes_relayed,
        }
    }

    #[test]
    fn combines_uptime_and_bandwidth() {
        // 5 minutes of uptime + 3 MiB relayed = 5 + 3 = 8 units.
        let units = to_billable_units(&sample(300, 3 * 1024 * 1024)).unwrap();
        assert_eq!(units, 8);
    }

    #[test]
    fn sub_threshold_remainders_earn_nothing() {
        // 59s uptime and 1 MiB minus a byte: both below one unit.
        let units = to_billable_units(&sample(59, 1024 * 1024 - 1)).unwrap();
        assert_eq!(units, 0);
    }

    #[test]
    fn large_sample_is_deterministic_and_does_not_overflow() {
        // The two quotients are each far below u64::MAX, so their sum is exact
        // (the saturating_add is defensive, not reached here). The point is
        // that an extreme sample yields a well-defined, overflow-free result.
        let units = to_billable_units(&sample(u64::MAX, u64::MAX)).unwrap();
        let expected =
            (u64::MAX / SECS_PER_UPTIME_UNIT).saturating_add(u64::MAX / BYTES_PER_BANDWIDTH_UNIT);
        assert_eq!(units, expected);
    }
}
