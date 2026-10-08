//! UDP handshake and hybrid session establishment. **Stub.**
//!
//! On a new connection the entry relay performs the hybrid key exchange
//! (classical ECDH + PQ KEM, combined in [`quantum_crypto::hybrid`]) and
//! derives the per-session record key. The peer's observed source address is
//! available at this point and is passed to the (consent-gated)
//! [`crate::audit_hook`] only when the operator has enabled it.

use crate::EngineError;
use dht_resolver::NodeId;
use std::net::SocketAddr;

/// The outcome of a completed handshake.
pub struct Session {
    /// The peer's cryptographic node id.
    pub peer: NodeId,
    /// The peer's observed transport address for this session.
    pub peer_addr: SocketAddr,
}

/// Perform the server side of the UDP handshake.
///
/// Stub: returns [`EngineError::NotImplemented`]. A real implementation runs
/// the hybrid KEM, authenticates the peer, and derives record keys via
/// [`quantum_crypto`].
pub async fn accept(_peer_addr: SocketAddr, _initial: &[u8]) -> Result<Session, EngineError> {
    // Reference the crypto pipeline the handshake will depend on so the
    // dependency is exercised; the combiner itself is implemented.
    let _ = quantum_crypto::hybrid::combine;
    Err(EngineError::NotImplemented("udp hybrid handshake"))
}
