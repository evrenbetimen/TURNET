//! Signed usage receipts and their verification.
//!
//! A provider node signs a [`SignedReceipt`] claiming the credits it earned in
//! a settlement window. Any peer holding the provider's public key can verify
//! the claim and apply it with [`crate::Ledger::settle_receipt`], which also
//! rejects replays via the per-node sequence number.
//!
//! This is the trust core of settlement; gossiping these receipts between
//! peers and resolving conflicts is the networked layer on top
//! ([`crate::Ledger::settle`]).

use crate::{Credits, LedgerError};
use dht_resolver::NodeId;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// A provider's signed claim of credits earned in one settlement window.
#[derive(Debug, Clone)]
pub struct SignedReceipt {
    /// The provider node being credited.
    pub node: NodeId,
    /// Credits claimed for this window.
    pub credits: Credits,
    /// Monotonic per-node window counter. A receipt is applied only when its
    /// `seq` exceeds the last applied for the node, so a replayed or
    /// out-of-order receipt cannot double-credit a window.
    pub seq: u64,
    /// Signature over [`receipt_bytes`] by the node's signing key.
    pub signature: Signature,
}

/// The canonical, domain-separated bytes that are signed and verified for a
/// receipt. Fixing this encoding keeps a signature meaningful across versions.
pub fn receipt_bytes(node: NodeId, credits: Credits, seq: u64) -> Vec<u8> {
    const DOMAIN: &[u8] = b"turnet-receipt-v1";
    let mut v = Vec::with_capacity(DOMAIN.len() + 24);
    v.extend_from_slice(DOMAIN);
    v.extend_from_slice(&node.0.to_be_bytes());
    v.extend_from_slice(&credits.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v
}

/// Sign a receipt for `node` with its signing key.
pub fn sign(key: &SigningKey, node: NodeId, credits: Credits, seq: u64) -> SignedReceipt {
    let signature = key.sign(&receipt_bytes(node, credits, seq));
    SignedReceipt {
        node,
        credits,
        seq,
        signature,
    }
}

/// Verify a receipt's signature against the provider's public key.
pub fn verify(key: &VerifyingKey, receipt: &SignedReceipt) -> Result<(), LedgerError> {
    let msg = receipt_bytes(receipt.node, receipt.credits, receipt.seq);
    key.verify(&msg, &receipt.signature)
        .map_err(|_| LedgerError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    #[test]
    fn valid_receipt_verifies() {
        let sk = key();
        let r = sign(&sk, NodeId(7), 500, 1);
        assert!(verify(&sk.verifying_key(), &r).is_ok());
    }

    #[test]
    fn tampered_receipt_fails() {
        let sk = key();
        let mut r = sign(&sk, NodeId(7), 500, 1);
        r.credits = 999; // tamper after signing
        assert!(matches!(
            verify(&sk.verifying_key(), &r),
            Err(LedgerError::BadSignature)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let r = sign(&key(), NodeId(7), 500, 1);
        let other = SigningKey::from_bytes(&[1u8; 32]);
        assert!(verify(&other.verifying_key(), &r).is_err());
    }
}
