//! Local audit store over SQLite (WAL mode).
//!
//! Each node keeps its own store on its own disk. The schema holds
//! [`crate::ConnectionRecord`] rows. WAL mode is used for crash-consistent,
//! append-friendly writes. This is operator-local storage, not a shared or
//! remote database.

use crate::{ComplianceError, ConnectionRecord};
use rusqlite::Connection;
use std::path::Path;

/// A handle to a node's local audit store.
pub struct AuditStore {
    conn: Connection,
}

impl AuditStore {
    /// Open (creating if absent) the audit store at `path` and enable WAL.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ComplianceError> {
        let conn = Connection::open(path).map_err(|e| ComplianceError::Storage(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| ComplianceError::Storage(e.to_string()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| ComplianceError::Storage(e.to_string()))?;
        Ok(Self { conn })
    }

    /// Open an in-memory store (for tests).
    pub fn open_in_memory() -> Result<Self, ComplianceError> {
        let conn =
            Connection::open_in_memory().map_err(|e| ComplianceError::Storage(e.to_string()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| ComplianceError::Storage(e.to_string()))?;
        Ok(Self { conn })
    }

    /// Append one connection record.
    pub fn append(&self, r: &ConnectionRecord) -> Result<(), ComplianceError> {
        self.conn
            .execute(
                "INSERT INTO connection_records \
                 (node_id_hex, observed_addr, ts_unix_micros, bytes, session_key_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    r.node_id_hex,
                    r.observed_addr,
                    r.ts_unix_micros as i64,
                    r.bytes as i64,
                    r.session_key_id,
                ],
            )
            .map_err(|e| ComplianceError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Count stored records.
    pub fn count(&self) -> Result<u64, ComplianceError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM connection_records", [], |row| row.get(0))
            .map_err(|e| ComplianceError::Storage(e.to_string()))?;
        Ok(n as u64)
    }

    /// Read all records back (used by the exporter).
    pub fn all(&self) -> Result<Vec<ConnectionRecord>, ComplianceError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT node_id_hex, observed_addr, ts_unix_micros, bytes, session_key_id \
                 FROM connection_records ORDER BY ts_unix_micros",
            )
            .map_err(|e| ComplianceError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ConnectionRecord {
                    node_id_hex: row.get(0)?,
                    observed_addr: row.get(1)?,
                    ts_unix_micros: row.get::<_, i64>(2)? as i128,
                    bytes: row.get::<_, i64>(3)? as u64,
                    session_key_id: row.get(4)?,
                })
            })
            .map_err(|e| ComplianceError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| ComplianceError::Storage(e.to_string()))?);
        }
        Ok(out)
    }
}

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS connection_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id_hex     TEXT NOT NULL,
    observed_addr   TEXT NOT NULL,
    ts_unix_micros  INTEGER NOT NULL,
    bytes           INTEGER NOT NULL,
    session_key_id  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_ts ON connection_records(ts_unix_micros);
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_read_back() {
        let store = AuditStore::open_in_memory().unwrap();
        assert_eq!(store.count().unwrap(), 0);
        store
            .append(&ConnectionRecord {
                node_id_hex: "000000000000abcd".into(),
                observed_addr: "198.51.100.7:51820".into(),
                ts_unix_micros: 1_700_000_000_000_000,
                bytes: 1420,
                session_key_id: "kid:9f2c".into(),
            })
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.all().unwrap().len(), 1);
    }
}
