//! # quantum_crypto — hybrid post-quantum cipher pipeline
//!
//! Turnet is designed to keep traffic confidential across a century-long
//! lifecycle, including against adversaries who record ciphertext today and
//! decrypt it once large-scale quantum computers arrive ("harvest now,
//! decrypt later"). The pipeline is therefore **hybrid**: a classical AEAD
//! for speed and a post-quantum KEM for forward-looking confidentiality, so
//! security holds as long as *either* primitive is unbroken.
//!
//! ## Layout
//! - [`aead`]    — ChaCha20-Poly1305 record encryption (the working primitive).
//! - [`kem`]     — ML-KEM / Kyber key encapsulation. **Stub only** — see below.
//! - [`hybrid`]  — combines a PQ-derived secret with the AEAD into one pipeline.
//! - [`transport`] — transport-fingerprint shaping (padding/timing). **Stub.**
//!
//! ## Status of the post-quantum half
//! [`kem`] is a documented placeholder. Wiring a real NIST ML-KEM (FIPS 203)
//! implementation is a deliberate, security-sensitive decision left to a
//! later milestone: the chosen crate must be audited, constant-time, and
//! pinned. Until then every `kem` entry point returns
//! [`CryptoError::NotImplemented`] rather than a weak placeholder, so there is
//! no risk of shipping a cipher that merely *looks* post-quantum.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Size in bytes of a 256-bit symmetric key.
pub const KEY_LEN: usize = 32;

/// Errors surfaced by the crypto pipeline.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// A primitive is intentionally not yet implemented in this scaffold.
    #[error("not implemented in scaffold: {0}")]
    NotImplemented(&'static str),
    /// AEAD open/seal failed (bad tag, wrong key, truncated input).
    #[error("aead operation failed")]
    Aead,
    /// Key material was the wrong length or shape.
    #[error("invalid key material")]
    InvalidKey,
}

/// AEAD record layer: ChaCha20-Poly1305 over the wire.
pub mod aead {
    use super::{CryptoError, KEY_LEN};
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    /// A sealing/opening context bound to one symmetric key.
    pub struct RecordCipher {
        cipher: ChaCha20Poly1305,
    }

    impl RecordCipher {
        /// Construct from a 32-byte key.
        pub fn new(key: &[u8; KEY_LEN]) -> Self {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
            Self { cipher }
        }

        /// Encrypt `plaintext` under a 96-bit `nonce`. The caller is
        /// responsible for never reusing a (key, nonce) pair.
        pub fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            self.cipher
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|_| CryptoError::Aead)
        }

        /// Decrypt and authenticate a record.
        pub fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            self.cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| CryptoError::Aead)
        }
    }
}

/// Post-quantum key encapsulation (ML-KEM / Kyber). **Stub.**
pub mod kem {
    use super::CryptoError;

    /// A PQ public encapsulation key. Opaque placeholder.
    pub struct EncapsulationKey(pub Vec<u8>);
    /// A PQ secret decapsulation key. Opaque placeholder.
    pub struct DecapsulationKey(pub Vec<u8>);
    /// A ciphertext carrying an encapsulated shared secret.
    pub struct Encapsulated(pub Vec<u8>);

    /// Generate an ML-KEM keypair.
    ///
    /// Stub: integrating an audited FIPS-203 implementation is a later
    /// milestone. Returns [`CryptoError::NotImplemented`].
    pub fn generate_keypair() -> Result<(EncapsulationKey, DecapsulationKey), CryptoError> {
        Err(CryptoError::NotImplemented("ml-kem keygen"))
    }

    /// Encapsulate a fresh shared secret to a public key.
    pub fn encapsulate(_ek: &EncapsulationKey) -> Result<(Encapsulated, [u8; 32]), CryptoError> {
        Err(CryptoError::NotImplemented("ml-kem encapsulate"))
    }

    /// Recover the shared secret from a ciphertext.
    pub fn decapsulate(_dk: &DecapsulationKey, _ct: &Encapsulated) -> Result<[u8; 32], CryptoError> {
        Err(CryptoError::NotImplemented("ml-kem decapsulate"))
    }
}

/// Hybrid handshake: fold a PQ shared secret into the AEAD key schedule.
pub mod hybrid {
    use super::{CryptoError, KEY_LEN};
    use sha2::{Digest, Sha256};

    /// Derive a 256-bit record key from a classical ECDH secret and a
    /// post-quantum KEM secret via a hash-based combiner. Either input alone
    /// being compromised must not reveal the output.
    ///
    /// The combiner itself is implemented; its PQ input comes from
    /// [`super::kem`], which is still a stub.
    pub fn combine(classical: &[u8], pq: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
        if classical.is_empty() || pq.is_empty() {
            return Err(CryptoError::InvalidKey);
        }
        let mut h = Sha256::new();
        h.update(b"turnet-hybrid-v1");
        h.update((classical.len() as u64).to_be_bytes());
        h.update(classical);
        h.update(pq);
        Ok(h.finalize().into())
    }
}

/// Transport shaping to resist passive traffic analysis. **Stub.**
///
/// Legitimate censorship-circumvention tools pad and re-time records so a
/// passive observer cannot fingerprint the protocol. This module is a
/// documented placeholder: the padding policy, its parameters, and the
/// trade-off against bandwidth are design decisions deferred to a later
/// milestone. Nothing here evades inspection today.
pub mod transport {
    use super::CryptoError;

    /// A record-padding policy.
    pub struct PaddingPolicy;

    impl PaddingPolicy {
        /// Return the padded length a record should be grown to. Stub.
        pub fn padded_len(&self, _actual: usize) -> Result<usize, CryptoError> {
            Err(CryptoError::NotImplemented("transport padding policy"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_round_trip() {
        let key = [7u8; KEY_LEN];
        let nonce = [1u8; 12];
        let cipher = aead::RecordCipher::new(&key);
        let ct = cipher.seal(&nonce, b"hello turnet").unwrap();
        let pt = cipher.open(&nonce, &ct).unwrap();
        assert_eq!(pt, b"hello turnet");
    }

    #[test]
    fn hybrid_combiner_is_deterministic() {
        let a = hybrid::combine(b"classical", b"pq").unwrap();
        let b = hybrid::combine(b"classical", b"pq").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn kem_is_stubbed() {
        assert!(kem::generate_keypair().is_err());
    }
}
