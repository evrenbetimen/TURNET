//! Defensive intrusion-tracking honeypot.
//!
//! A defensive honeypot detects unauthorized probes against the operator's
//! **own** node — repeated connection attempts to a decoy endpoint the node
//! exposes. It is scoped strictly as a defensive sensor for the operator's own
//! infrastructure: it records only what hits this node, and it is not a tool
//! for tracking ordinary users of the network.
//!
//! This implementation is an in-memory counter: feed it the source of each
//! observed probe with [`Honeypot::observe`]; once a source crosses the
//! configured threshold it is flagged. Persisting flags or wiring a real decoy
//! listener is left to integration with the relay engine.

use std::collections::HashMap;

/// A flagged source that has probed this node past the threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrusionFlag {
    /// The probe source (e.g. an address), as observed by this node.
    pub source: String,
    /// How many probes have been seen from this source.
    pub count: u32,
    /// Short human-readable description.
    pub summary: String,
}

/// A defensive honeypot sensor for this node.
pub struct Honeypot {
    threshold: u32,
    seen: HashMap<String, u32>,
}

impl Honeypot {
    /// Create a sensor that flags a source after `threshold` probes.
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold: threshold.max(1),
            seen: HashMap::new(),
        }
    }

    /// Record one probe from `source`. Returns a flag the first time (and only
    /// the first time) the source reaches the threshold.
    pub fn observe(&mut self, source: &str) -> Option<IntrusionFlag> {
        let count = self.seen.entry(source.to_string()).or_insert(0);
        *count += 1;
        if *count == self.threshold {
            Some(IntrusionFlag {
                source: source.to_string(),
                count: *count,
                summary: format!("{} probes from {} reached threshold", count, source),
            })
        } else {
            None
        }
    }

    /// All sources currently at or above the threshold.
    pub fn flags(&self) -> Vec<IntrusionFlag> {
        let mut out: Vec<IntrusionFlag> = self
            .seen
            .iter()
            .filter(|(_, &c)| c >= self.threshold)
            .map(|(source, &count)| IntrusionFlag {
                source: source.clone(),
                count,
                summary: format!("{} probes from {}", count, source),
            })
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.source.cmp(&b.source)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_after_threshold() {
        let mut h = Honeypot::new(3);
        assert_eq!(h.observe("203.0.113.9"), None);
        assert_eq!(h.observe("203.0.113.9"), None);
        let flag = h.observe("203.0.113.9").expect("should flag on 3rd");
        assert_eq!(flag.count, 3);
        // Does not re-flag on subsequent probes.
        assert_eq!(h.observe("203.0.113.9"), None);
        assert_eq!(h.flags().len(), 1);
    }

    #[test]
    fn distinct_sources_tracked_separately() {
        let mut h = Honeypot::new(2);
        h.observe("a");
        h.observe("b");
        assert!(h.flags().is_empty());
    }
}
