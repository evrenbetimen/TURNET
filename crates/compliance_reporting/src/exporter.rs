//! Signed export of audit records for review under lawful process.
//!
//! Produces a JSON or CSV bundle of [`crate::ConnectionRecord`]s plus an
//! Ed25519 signature over the serialized bytes, so a recipient can verify the
//! export was produced by the holder of the operator's signing key and was
//! not altered in transit. Signing provides integrity and attribution; it is
//! not access control.

use std::path::{Path, PathBuf};

use crate::{ComplianceError, ConnectionRecord};
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

// Re-exported so downstream crates (e.g. the Tauri backend) can name the key
// types without taking a direct dependency on ed25519-dalek.
pub use ed25519_dalek::{SigningKey, VerifyingKey};

/// Generate a fresh Ed25519 signing key from the OS CSPRNG.
///
/// A real deployment loads a persisted operator key from secure storage; this
/// helper is for first-run/bootstrap and tests.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// Output format for an export bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Structured JSON.
    Json,
    /// Flat CSV (one row per record).
    Csv,
}

/// A signed export: the payload bytes and a detached signature over them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedExport {
    /// Format of `payload`.
    pub format: &'static str,
    /// The serialized records.
    pub payload: Vec<u8>,
    /// Ed25519 signature over `payload`, hex-encoded.
    pub signature_hex: String,
}

/// Serialize `records` in `format` and sign them with `key`.
pub fn export_signed(
    records: &[ConnectionRecord],
    format: Format,
    key: &SigningKey,
) -> Result<SignedExport, ComplianceError> {
    let (payload, fmt) = match format {
        Format::Json => (
            serde_json::to_vec_pretty(records)
                .map_err(|e| ComplianceError::Export(e.to_string()))?,
            "json",
        ),
        Format::Csv => (to_csv(records)?, "csv"),
    };
    let sig: Signature = key.sign(&payload);
    Ok(SignedExport {
        format: fmt,
        payload,
        signature_hex: hex_encode(&sig.to_bytes()),
    })
}

/// Verify a signed export against a public key. Returns `true` when the
/// signature covers `payload` exactly.
pub fn verify(export: &SignedExport, vk: &VerifyingKey) -> bool {
    let bytes = match hex_decode(&export.signature_hex) {
        Some(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    let sig = Signature::from_bytes(&arr);
    vk.verify(&export.payload, &sig).is_ok()
}

/// Write a signed export to `dir`, producing `<stem>.<format>` for the payload
/// and `<stem>.<format>.sig` for the detached hex signature. Returns the
/// payload path.
pub fn write_to_dir(
    export: &SignedExport,
    dir: &Path,
    stem: &str,
) -> Result<PathBuf, ComplianceError> {
    std::fs::create_dir_all(dir).map_err(|e| ComplianceError::Export(e.to_string()))?;
    let payload_path = dir.join(format!("{stem}.{}", export.format));
    let sig_path = dir.join(format!("{stem}.{}.sig", export.format));
    std::fs::write(&payload_path, &export.payload)
        .map_err(|e| ComplianceError::Export(e.to_string()))?;
    std::fs::write(&sig_path, export.signature_hex.as_bytes())
        .map_err(|e| ComplianceError::Export(e.to_string()))?;
    Ok(payload_path)
}

fn to_csv(records: &[ConnectionRecord]) -> Result<Vec<u8>, ComplianceError> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record(["node_id_hex", "observed_addr", "ts_unix_micros", "bytes", "session_key_id"])
        .map_err(|e| ComplianceError::Export(e.to_string()))?;
    for r in records {
        wtr.write_record([
            r.node_id_hex.as_str(),
            r.observed_addr.as_str(),
            &r.ts_unix_micros.to_string(),
            &r.bytes.to_string(),
            r.session_key_id.as_str(),
        ])
        .map_err(|e| ComplianceError::Export(e.to_string()))?;
    }
    wtr.into_inner()
        .map_err(|e| ComplianceError::Export(e.to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<ConnectionRecord> {
        vec![ConnectionRecord {
            node_id_hex: "000000000000abcd".into(),
            observed_addr: "198.51.100.7:51820".into(),
            ts_unix_micros: 1_700_000_000_000_000,
            bytes: 1420,
            session_key_id: "kid:9f2c".into(),
        }]
    }

    #[test]
    fn signed_json_verifies() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let export = export_signed(&sample(), Format::Json, &key).unwrap();
        assert_eq!(export.format, "json");
        assert!(verify(&export, &key.verifying_key()));
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut export = export_signed(&sample(), Format::Json, &key).unwrap();
        export.payload.push(b'!'); // tamper
        assert!(!verify(&export, &key.verifying_key()));
    }

    #[test]
    fn generated_key_round_trips() {
        let key = generate_signing_key();
        let export = export_signed(&sample(), Format::Csv, &key).unwrap();
        assert!(verify(&export, &key.verifying_key()));
    }

    #[test]
    fn csv_has_header() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let export = export_signed(&sample(), Format::Csv, &key).unwrap();
        let text = String::from_utf8(export.payload).unwrap();
        assert!(text.starts_with("node_id_hex,"));
    }
}
