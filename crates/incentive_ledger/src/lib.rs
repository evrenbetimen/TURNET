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
//! - [`settlement`] — signed usage receipts and their verifiable application.
//!
//! The arithmetic uses saturating integer credits (no floats) so the ledger
//! stays deterministic across platforms over a long lifecycle. The apply-step,
//! metering ingestion ([`Ledger::ingest`]), and the local verify-and-apply
//! half of settlement ([`Ledger::settle_receipt`]) are implemented; the
//! networked distribution path (gossiping receipts between peers, conflict
//! resolution) remains a stub in [`Ledger::settle`].

#![forbid(unsafe_code)]

use dht_resolver::NodeId;
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use thiserror::Error;

pub mod meter;
pub mod policy;
pub mod settlement;

/// Errors from the ledger.
#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("not implemented in scaffold: {0}")]
    NotImplemented(&'static str),
    #[error("insufficient balance")]
    InsufficientBalance,
    /// A receipt's signature did not verify against the node's public key.
    #[error("invalid receipt signature")]
    BadSignature,
    /// A receipt was older than (or equal to) one already applied for its
    /// node; applying it would double-count.
    #[error("stale or replayed receipt")]
    StaleReceipt,
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
    /// Highest settlement-window sequence already applied per node, so a
    /// replayed or out-of-order receipt cannot credit the same window twice.
    applied_seq: HashMap<NodeId, u64>,
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

    /// Ingest one raw usage sample: meter it into billable units, price it
    /// through `policy`, and credit the reporting node. Returns the node's new
    /// balance. This is the local metering path; the sample's delivery from the
    /// live relay is [`crate::settlement`] / networking's job.
    pub fn ingest(
        &mut self,
        sample: &meter::UsageSample,
        policy: &policy::RatePolicy,
    ) -> Result<Credits, LedgerError> {
        let units = meter::to_billable_units(sample)?;
        let credits = policy.credits_for(units);
        self.apply(Entry::Earn {
            node: sample.node,
            amount: credits,
        })
    }

    /// Verify a signed usage receipt against the provider's public key and, if
    /// it is newer than the last applied window for that node, credit it.
    ///
    /// This is the local, verifiable half of settlement: signature-checked and
    /// replay-resistant (via the per-node sequence). Returns the node's new
    /// balance, [`LedgerError::BadSignature`] if the signature fails, or
    /// [`LedgerError::StaleReceipt`] if the window was already applied.
    pub fn settle_receipt(
        &mut self,
        key: &VerifyingKey,
        receipt: &settlement::SignedReceipt,
    ) -> Result<Credits, LedgerError> {
        settlement::verify(key, receipt)?;
        let last = self.applied_seq.get(&receipt.node).copied().unwrap_or(0);
        if receipt.seq <= last {
            return Err(LedgerError::StaleReceipt);
        }
        self.applied_seq.insert(receipt.node, receipt.seq);
        self.apply(Entry::Earn {
            node: receipt.node,
            amount: receipt.credits,
        })
    }

    /// Gossip receipts to peers and reconcile balances across the network.
    ///
    /// Stub: the networked distribution protocol (peer gossip of the receipts
    /// that [`Self::settle_receipt`] verifies, plus conflict resolution) is a
    /// later milestone. The local verify-and-apply step it builds on is
    /// implemented.
    pub async fn settle(&mut self) -> Result<(), LedgerError> {
        Err(LedgerError::NotImplemented(
            "network credit settlement gossip",
        ))
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

    #[test]
    fn ingest_meters_prices_and_credits() {
        let node = NodeId(3);
        let mut l = Ledger::new();
        // 10 minutes uptime + 2 MiB = 10 + 2 = 12 units, at 1 credit/unit.
        let sample = meter::UsageSample {
            node,
            uptime_secs: 600,
            bytes_relayed: 2 * 1024 * 1024,
        };
        let bal = l.ingest(&sample, &policy::RatePolicy::default()).unwrap();
        assert_eq!(bal, 12);
        assert_eq!(l.balance(node), 12);
    }

    #[test]
    fn settle_receipt_applies_once_and_rejects_replay() {
        use ed25519_dalek::SigningKey;
        let node = NodeId(4);
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let vk = sk.verifying_key();
        let mut l = Ledger::new();

        let r1 = settlement::sign(&sk, node, 100, 1);
        assert_eq!(l.settle_receipt(&vk, &r1).unwrap(), 100);
        // Replaying the same (or an older) window is rejected.
        assert!(matches!(
            l.settle_receipt(&vk, &r1),
            Err(LedgerError::StaleReceipt)
        ));
        // A newer window accrues.
        let r2 = settlement::sign(&sk, node, 50, 2);
        assert_eq!(l.settle_receipt(&vk, &r2).unwrap(), 150);
    }

    #[test]
    fn settle_receipt_rejects_bad_signature() {
        use ed25519_dalek::SigningKey;
        let node = NodeId(5);
        let sk = SigningKey::from_bytes(&[6u8; 32]);
        let wrong = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let mut l = Ledger::new();
        let r = settlement::sign(&sk, node, 100, 1);
        assert!(matches!(
            l.settle_receipt(&wrong, &r),
            Err(LedgerError::BadSignature)
        ));
        assert_eq!(l.balance(node), 0);
    }
}
