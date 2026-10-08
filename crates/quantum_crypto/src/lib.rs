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
    /// A record exceeded the configured maximum padded size.
    #[error("record too large to pad")]
    TooLarge,
    /// A padded record was malformed (bad length header).
    #[error("malformed padded record")]
    MalformedPadded,
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

/// Transport shaping to resist passive traffic analysis.
///
/// Padding record plaintext up to fixed size buckets means a passive observer
/// (including the user's own ISP) learns far less from packet sizes about what
/// a user is doing. This is a **user-privacy** measure — uniform record sizes
/// — not a tool for hiding the protocol's existence or defeating lawful
/// inspection.
///
/// The wire format is a 4-byte little-endian original-length header followed
/// by the plaintext and zero padding, the whole rounded up to a multiple of
/// `bucket`. [`PaddingPolicy::unpad`] recovers the exact original bytes.
pub mod transport {
    use super::CryptoError;

    /// 4-byte length header prepended before padding.
    const HEADER: usize = 4;

    /// A record-padding policy: round every record up to a multiple of
    /// `bucket` bytes, refusing anything whose padded size would exceed `max`.
    #[derive(Debug, Clone, Copy)]
    pub struct PaddingPolicy {
        /// Bucket granularity in bytes (records are rounded up to a multiple).
        pub bucket: usize,
        /// Maximum padded record size in bytes.
        pub max: usize,
    }

    impl Default for PaddingPolicy {
        fn default() -> Self {
            Self { bucket: 256, max: 65535 }
        }
    }

    impl PaddingPolicy {
        /// Compute the on-wire padded length for a plaintext of `actual` bytes
        /// (including the 4-byte length header).
        pub fn padded_len(&self, actual: usize) -> Result<usize, CryptoError> {
            let bucket = self.bucket.max(1);
            let needed = actual
                .checked_add(HEADER)
                .ok_or(CryptoError::TooLarge)?;
            let padded = needed.div_ceil(bucket) * bucket;
            if padded > self.max {
                return Err(CryptoError::TooLarge);
            }
            Ok(padded)
        }

        /// Pad `data` to the next bucket boundary, embedding its true length.
        pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let target = self.padded_len(data.len())?;
            let mut out = Vec::with_capacity(target);
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
            out.resize(target, 0);
            Ok(out)
        }

        /// Recover the original bytes from a padded record.
        pub fn unpad(&self, padded: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if padded.len() < HEADER {
                return Err(CryptoError::MalformedPadded);
            }
            let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
            let end = HEADER.checked_add(len).ok_or(CryptoError::MalformedPadded)?;
            if end > padded.len() {
                return Err(CryptoError::MalformedPadded);
            }
            Ok(padded[HEADER..end].to_vec())
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

    #[test]
    fn padding_rounds_to_bucket_and_round_trips() {
        let p = transport::PaddingPolicy { bucket: 256, max: 65535 };
        let data = b"a short message";
        let padded = p.pad(data).unwrap();
        assert_eq!(padded.len(), 256); // 4 + 15 -> rounded up to 256
        assert_eq!(p.unpad(&padded).unwrap(), data);
    }

    #[test]
    fn padding_rejects_oversize() {
        let p = transport::PaddingPolicy { bucket: 256, max: 512 };
        assert!(p.pad(&vec![0u8; 600]).is_err());
    }

    #[test]
    fn unpad_rejects_malformed() {
        let p = transport::PaddingPolicy::default();
        assert!(p.unpad(&[1, 2]).is_err()); // shorter than header
    }
}
