//! Signed export of audit records for review under lawful process.
//!
//! Produces a JSON or CSV bundle of [`crate::ConnectionRecord`]s plus an
//! Ed25519 signature over the serialized bytes, so a recipient can verify the
//! export was produced by the holder of the operator's signing key and was
//! not altered in transit. Signing provides integrity and attribution; it is
//! not access control.

use crate::{ComplianceError, ConnectionRecord};
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};

// Re-exported so downstream crates (e.g. the Tauri backend) can name the
// signing key type without taking a direct dependency on ed25519-dalek.
pub use ed25519_dalek::SigningKey;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

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
        let vk: VerifyingKey = key.verifying_key();
        let export = export_signed(&sample(), Format::Json, &key).unwrap();
        assert_eq!(export.format, "json");
        let sig_bytes: [u8; 64] = {
            let raw = (0..64)
                .map(|i| u8::from_str_radix(&export.signature_hex[i * 2..i * 2 + 2], 16).unwrap())
                .collect::<Vec<_>>();
            raw.try_into().unwrap()
        };
        let sig = Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(&export.payload, &sig).is_ok());
    }

    #[test]
    fn csv_has_header() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let export = export_signed(&sample(), Format::Csv, &key).unwrap();
        let text = String::from_utf8(export.payload).unwrap();
        assert!(text.starts_with("node_id_hex,"));
    }
}
