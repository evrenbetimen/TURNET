//! # dht_resolver — in-network addressing over a Kademlia DHT
//!
//! Turnet resolves human-readable names (`myhandle.tur`) to the 64-bit
//! cryptographic Node IDs that identify relay nodes, **without** any
//! centralized DNS registry. The backbone is a `libp2p` Kademlia DHT; this
//! crate owns the name→NodeID record format and the resolve/announce API.
//!
//! ## Modules
//! - [`resolver`]  — map a `.tur` name to live [`NodeId`]s (anycast-aware).
//! - [`anycast`]   — multi-node mirror routing across identical replicas.
//! - [`claim`]     — anti-squatting: prove ownership of a legacy clear-web
//!   TLS certificate chain (via a zero-knowledge proof) to lock a matching
//!   `.tur` handle. **Stub.**
//!
//! `libp2p` is wired in as the transport/DHT dependency; the Kademlia
//! behaviour, swarm wiring, and record validation are scaffold stubs.

#![forbid(unsafe_code)]

use thiserror::Error;

/// A 64-bit cryptographic node identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64);

impl NodeId {
    /// Render as zero-padded hex, the canonical wire form.
    pub fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

/// Errors from name resolution and record handling.
#[derive(Debug, Error)]
pub enum DhtError {
    #[error("not implemented in scaffold: {0}")]
    NotImplemented(&'static str),
    #[error("name not found in dht")]
    NotFound,
    #[error("invalid turnet name: {0}")]
    InvalidName(String),
}

/// Normalize and validate a Turnet name, returning the lookup key.
///
/// Rejects empty labels and names whose final label is not a Turnet TLD.
pub fn normalize_name(name: &str) -> Result<String, DhtError> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.split('.').any(|l| l.is_empty()) {
        return Err(DhtError::InvalidName(name));
    }
    match name.rsplit('.').next() {
        Some("tur") | Some("vps") | Some("cpt") => Ok(name),
        _ => Err(DhtError::InvalidName(name)),
    }
}

/// Name resolution against the DHT.
pub mod resolver {
    use super::{DhtError, NodeId};

    /// Handle to a running DHT resolver task.
    pub struct Resolver;

    impl Resolver {
        /// Look up the live Node IDs currently serving `name`.
        ///
        /// Stub: returns [`DhtError::NotImplemented`] until the Kademlia
        /// behaviour is wired to the swarm.
        pub async fn resolve(&self, _name: &str) -> Result<Vec<NodeId>, DhtError> {
            Err(DhtError::NotImplemented("kademlia resolve"))
        }

        /// Announce that this node serves `name`.
        pub async fn announce(&self, _name: &str, _node: NodeId) -> Result<(), DhtError> {
            Err(DhtError::NotImplemented("kademlia announce"))
        }
    }
}

/// Mesh anycast: balance a name across identical microVM replicas.
pub mod anycast {
    use super::{DhtError, NodeId};

    /// Pick a replica for a name given a set of healthy candidates.
    ///
    /// The policy here is deliberately simple and **deterministic**: the
    /// numerically smallest [`NodeId`] wins. A deterministic choice means every
    /// resolver that sees the same healthy set routes a given name to the same
    /// replica, which keeps a name's traffic affine to one mirror without any
    /// coordination. Latency-, load-, and hash-ring-aware selection (so that
    /// different names spread across mirrors) is a later milestone that will
    /// take richer per-candidate inputs than this signature carries.
    ///
    /// Returns [`DhtError::NotFound`] when there are no candidates.
    pub fn select(candidates: &[NodeId]) -> Result<NodeId, DhtError> {
        candidates
            .iter()
            .copied()
            .min_by_key(|n| n.0)
            .ok_or(DhtError::NotFound)
    }
}

/// Anti-squatting handle claims via zero-knowledge TLS-log proofs. **Stub.**
pub mod claim {
    use super::DhtError;

    /// A request to lock a `.tur` handle by proving control of the matching
    /// legacy clear-web domain's certificate chain.
    pub struct HandleClaim {
        /// The handle being claimed, e.g. `acme.tur`.
        pub handle: String,
        /// The legacy domain whose TLS certificate logs back the claim.
        pub legacy_domain: String,
    }

    impl HandleClaim {
        /// Verify the zero-knowledge proof backing this claim.
        ///
        /// Stub: the ZK circuit and certificate-transparency verification are
        /// deferred. Returns [`DhtError::NotImplemented`].
        pub fn verify(&self, _proof: &[u8]) -> Result<bool, DhtError> {
            Err(DhtError::NotImplemented("zk handle-claim proof"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_hex_is_padded() {
        assert_eq!(NodeId(0xABCD).to_hex(), "000000000000abcd");
    }

    #[test]
    fn normalize_accepts_turnet_names() {
        assert_eq!(
            normalize_name("Shop.Example.TUR.").unwrap(),
            "shop.example.tur"
        );
    }

    #[test]
    fn normalize_rejects_clear_web() {
        assert!(normalize_name("example.com").is_err());
        assert!(normalize_name("").is_err());
    }

    #[test]
    fn anycast_empty_is_not_found() {
        assert!(matches!(anycast::select(&[]), Err(DhtError::NotFound)));
    }

    #[test]
    fn anycast_is_deterministic_and_order_independent() {
        let a = NodeId(0x30);
        let b = NodeId(0x10);
        let c = NodeId(0x20);
        // Smallest NodeId wins regardless of input ordering.
        assert_eq!(anycast::select(&[a, b, c]).unwrap(), b);
        assert_eq!(anycast::select(&[c, a, b]).unwrap(), b);
        assert_eq!(anycast::select(&[b]).unwrap(), b);
    }
}
