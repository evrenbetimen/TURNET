//! # incentive_ledger — uptime & bandwidth credit state machine
//!
//! Provider nodes earn Network Credits for the uptime and bandwidth they
//! contribute; those credits fuel the in-network compute marketplace. This
//! crate is the accounting core: it ingests signed usage reports, applies a
//! credit policy, and tracks per-node balances.
//!
//! ## Modules
//! - [`meter`]   — turn raw uptime/throughput samples into billable units.
//! - [`ledger`]  — the balance state machine (credit/debit, double-entry).
//! - [`policy`]  — the (tunable) rate schedule converting units to credits.
//!
//! The arithmetic uses saturating integer credits (no floats) so the ledger
//! stays deterministic across platforms over a long lifecycle. The state
//! machine's apply-step is implemented; metering ingestion and the network
//! settlement/distribution path are stubs.

#![forbid(unsafe_code)]

use dht_resolver::NodeId;
use std::collections::HashMap;
use thiserror::Error;

pub mod meter;
pub mod policy;

/// Errors from the ledger.
#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("not implemented in scaffold: {0}")]
    NotImplemented(&'static str),
    #[error("insufficient balance")]
    InsufficientBalance,
}

/// A credit amount (integer, saturating).
pub type Credits = u64;

/// A ledger entry to apply.
#[derive(Debug, Clone, Copy)]
pub enum Entry {
    /// Credit a node for contributed service.
    Earn { node: NodeId, amount: Credits },
    /// Debit a node for consuming marketplace compute.
    Spend { node: NodeId, amount: Credits },
}

/// In-memory balance state machine.
#[derive(Debug, Default)]
pub struct Ledger {
    balances: HashMap<NodeId, Credits>,
}

impl Ledger {
    /// New empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current balance for a node (0 if unseen).
    pub fn balance(&self, node: NodeId) -> Credits {
        *self.balances.get(&node).unwrap_or(&0)
    }

    /// Apply one entry, returning the node's new balance.
    pub fn apply(&mut self, entry: Entry) -> Result<Credits, LedgerError> {
        match entry {
            Entry::Earn { node, amount } => {
                let b = self.balances.entry(node).or_insert(0);
                *b = b.saturating_add(amount);
                Ok(*b)
            }
            Entry::Spend { node, amount } => {
                let b = self.balances.entry(node).or_insert(0);
                if *b < amount {
                    return Err(LedgerError::InsufficientBalance);
                }
                *b -= amount;
                Ok(*b)
            }
        }
    }

    /// Settle and distribute credits across the network.
    ///
    /// Stub: the networked settlement protocol (gossip of signed receipts,
    /// conflict resolution) is a later milestone.
    pub async fn settle(&mut self) -> Result<(), LedgerError> {
        Err(LedgerError::NotImplemented("network credit settlement"))
    }
}

/// The balance state machine — alias for discoverability from docs.
pub mod ledger {
    pub use super::{Entry, Ledger};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earn_then_spend() {
        let node = NodeId(1);
        let mut l = Ledger::new();
        assert_eq!(l.apply(Entry::Earn { node, amount: 100 }).unwrap(), 100);
        assert_eq!(l.apply(Entry::Spend { node, amount: 40 }).unwrap(), 60);
        assert_eq!(l.balance(node), 60);
    }

    #[test]
    fn overspend_is_rejected() {
        let node = NodeId(2);
        let mut l = Ledger::new();
        l.apply(Entry::Earn { node, amount: 10 }).unwrap();
        assert!(l.apply(Entry::Spend { node, amount: 11 }).is_err());
    }
}
