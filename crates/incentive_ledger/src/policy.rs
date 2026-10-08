//! Credit rate policy: billable units → [`crate::Credits`].
//!
//! Kept as data so the rate schedule can be tuned/governed without code
//! changes. The default here is a simple linear rate; real deployments will
//! replace it with a governed schedule.

use crate::Credits;

/// A linear credit rate schedule.
#[derive(Debug, Clone, Copy)]
pub struct RatePolicy {
    /// Credits awarded per billable unit.
    pub credits_per_unit: u64,
}

impl Default for RatePolicy {
    fn default() -> Self {
        Self { credits_per_unit: 1 }
    }
}

impl RatePolicy {
    /// Convert billable units to credits (saturating).
    pub fn credits_for(&self, units: u64) -> Credits {
        units.saturating_mul(self.credits_per_unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rate_is_linear() {
        assert_eq!(RatePolicy::default().credits_for(5), 5);
    }
}
