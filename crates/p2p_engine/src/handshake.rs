//! UDP handshake and hybrid session establishment.
//!
//! A new session is established with a one-round-trip **hybrid** key agreement:
//! the classical half is X25519 ECDH and the post-quantum half is ML-KEM-768
//! ([`quantum_crypto::kem`]). Both shared secrets are folded together by
//! [`quantum_crypto::hybrid::combine`], so the derived record key stays secret
//! unless *both* primitives are broken.
//!
//! ```text
//! initiator                                     responder
//!   ClientHello { x25519_pub, mlkem_ek }  ───▶
//!                                         ◀───  ServerHello { x25519_pub, mlkem_ct }
//!   derive key = combine(ECDH, decaps(ct))      derive key = combine(ECDH, encaps secret)
//! ```
//!
//! This establishes a confidential channel but does **not** yet authenticate
//! the peer: binding the session to a long-term identity key (so a
//! man-in-the-middle is detected) is the next layer. Until then the peer id is
//! a *provisional* transport id derived from the peer's ephemeral public key,
//! not a verified identity. The peer's observed source address is available to
//! the consent-gated [`crate::audit_hook`] only when the operator enabled it.

use crate::EngineError;
use dht_resolver::NodeId;
use quantum_crypto::kem;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// X25519 public key length.
const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key length (FIPS 203).
const MLKEM_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
const MLKEM_CT_LEN: usize = 1088;

const CLIENT_HELLO_LEN: usize = X25519_LEN + MLKEM_EK_LEN;
const SERVER_HELLO_LEN: usize = X25519_LEN + MLKEM_CT_LEN;

/// A completed, confidential session.
pub struct Session {
    /// The peer's (provisional) node id, derived from its ephemeral key.
    pub peer: NodeId,
    /// The peer's observed transport address for this session.
    pub peer_addr: SocketAddr,
    /// The 256-bit per-session record key from the hybrid combiner.
    pub session_key: [u8; 32],
}

/// A provisional transport id derived from the peer's ephemeral X25519 key.
/// Not an authenticated identity — see the module docs.
fn provisional_node_id(pubkey: &[u8; 32]) -> NodeId {
    let mut head = [0u8; 8];
    head.copy_from_slice(&pubkey[..8]);
    NodeId(u64::from_be_bytes(head))
}

/// The initiator's in-flight handshake state (its ephemeral secrets).
pub struct Initiator {
    x_secret: EphemeralSecret,
    x_public: PublicKey,
    kem_ek: kem::EncapsulationKey,
    kem_dk: kem::DecapsulationKey,
}

/// The crypto outcome of a handshake half, before it is bound to a transport
/// address to form a [`Session`].
pub struct Derived {
    peer_pub: [u8; 32],
    /// The agreed 256-bit record key.
    pub session_key: [u8; 32],
}

impl Initiator {
    /// Generate fresh ephemeral X25519 and ML-KEM key material.
    pub fn new() -> Result<Self, EngineError> {
        let x_secret = EphemeralSecret::random();
        let x_public = PublicKey::from(&x_secret);
        let (kem_ek, kem_dk) =
            kem::generate_keypair().map_err(|_| EngineError::HandshakeRejected)?;
        Ok(Self {
            x_secret,
            x_public,
            kem_ek,
            kem_dk,
        })
    }

    /// The `ClientHello` bytes to send: X25519 public key ++ ML-KEM enc key.
    pub fn client_hello(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(CLIENT_HELLO_LEN);
        v.extend_from_slice(self.x_public.as_bytes());
        v.extend_from_slice(&self.kem_ek.0);
        v
    }

    /// Consume the `ServerHello` and derive the shared session key.
    pub fn finish(self, server_hello: &[u8]) -> Result<Derived, EngineError> {
        if server_hello.len() != SERVER_HELLO_LEN {
            return Err(EngineError::MalformedHandshake);
        }
        let Initiator {
            x_secret, kem_dk, ..
        } = self;
        let mut their_x = [0u8; X25519_LEN];
        their_x.copy_from_slice(&server_hello[..X25519_LEN]);
        let ct = kem::Encapsulated(server_hello[X25519_LEN..].to_vec());
        let pq = kem::decapsulate(&kem_dk, &ct).map_err(|_| EngineError::HandshakeRejected)?;
        let classical = x_secret.diffie_hellman(&PublicKey::from(their_x));
        let session_key = quantum_crypto::hybrid::combine(classical.as_bytes(), &pq)
            .map_err(|_| EngineError::HandshakeRejected)?;
        Ok(Derived {
            peer_pub: their_x,
            session_key,
        })
    }
}

/// Responder side: consume a `ClientHello`, returning the `ServerHello` to send
/// back and the derived session key.
pub fn respond(client_hello: &[u8]) -> Result<(Vec<u8>, Derived), EngineError> {
    if client_hello.len() != CLIENT_HELLO_LEN {
        return Err(EngineError::MalformedHandshake);
    }
    let mut client_x = [0u8; X25519_LEN];
    client_x.copy_from_slice(&client_hello[..X25519_LEN]);
    let client_ek = kem::EncapsulationKey(client_hello[X25519_LEN..].to_vec());

    let x_secret = EphemeralSecret::random();
    let x_public = PublicKey::from(&x_secret);
    let (ct, pq) = kem::encapsulate(&client_ek).map_err(|_| EngineError::HandshakeRejected)?;
    let classical = x_secret.diffie_hellman(&PublicKey::from(client_x));
    let session_key = quantum_crypto::hybrid::combine(classical.as_bytes(), &pq)
        .map_err(|_| EngineError::HandshakeRejected)?;

    let mut server_hello = Vec::with_capacity(SERVER_HELLO_LEN);
    server_hello.extend_from_slice(x_public.as_bytes());
    server_hello.extend_from_slice(&ct.0);
    Ok((
        server_hello,
        Derived {
            peer_pub: client_x,
            session_key,
        },
    ))
}

/// Initiate a handshake to `peer` over `socket` and return the session.
pub async fn connect(socket: &UdpSocket, peer: SocketAddr) -> Result<Session, EngineError> {
    let initiator = Initiator::new()?;
    socket.send_to(&initiator.client_hello(), peer).await?;
    let mut buf = [0u8; 2048];
    let (n, from) = socket.recv_from(&mut buf).await?;
    let derived = initiator.finish(&buf[..n])?;
    Ok(Session {
        peer: provisional_node_id(&derived.peer_pub),
        peer_addr: from,
        session_key: derived.session_key,
    })
}

/// Accept one inbound handshake on `socket` and return the session.
pub async fn accept(socket: &UdpSocket) -> Result<Session, EngineError> {
    let mut buf = [0u8; 2048];
    let (n, from) = socket.recv_from(&mut buf).await?;
    let (server_hello, derived) = respond(&buf[..n])?;
    socket.send_to(&server_hello, from).await?;
    Ok(Session {
        peer: provisional_node_id(&derived.peer_pub),
        peer_addr: from,
        session_key: derived.session_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_handshake_agrees_on_key() {
        let initiator = Initiator::new().unwrap();
        let hello = initiator.client_hello();
        assert_eq!(hello.len(), CLIENT_HELLO_LEN);
        let (server_hello, resp) = respond(&hello).unwrap();
        assert_eq!(server_hello.len(), SERVER_HELLO_LEN);
        let fin = initiator.finish(&server_hello).unwrap();
        // Both sides derive the same record key.
        assert_eq!(fin.session_key, resp.session_key);
    }

    #[test]
    fn rejects_malformed_hello() {
        assert!(matches!(
            respond(&[0u8; 10]),
            Err(EngineError::MalformedHandshake)
        ));
        let initiator = Initiator::new().unwrap();
        assert!(matches!(
            initiator.finish(&[0u8; 10]),
            Err(EngineError::MalformedHandshake)
        ));
    }

    #[tokio::test]
    async fn udp_round_trip_agrees_on_key() {
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resp_addr = responder.local_addr().unwrap();
        let server = tokio::spawn(async move { accept(&responder).await });

        let initiator = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_session = connect(&initiator, resp_addr).await.unwrap();
        let server_session = server.await.unwrap().unwrap();

        assert_eq!(client_session.session_key, server_session.session_key);
        // Each side sees the other's address.
        assert_eq!(client_session.peer_addr, resp_addr);
    }
}
