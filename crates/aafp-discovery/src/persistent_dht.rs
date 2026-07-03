//! Persistent capability DHT backed by SQLite.
//!
//! AgentRecords are stored in a SQLite database and survive process
//! restarts. This implements the "Persistent/networked DHT" outstanding
//! item from PROTOCOL_CANDIDATE_CHECKLIST.md.

#![allow(deprecated)]

use crate::capability_dht::DhtError;
use aafp_identity::agent_record::AgentRecord;
use aafp_identity::AgentId;
use rusqlite::{params, Connection};

/// Persistent capability DHT backed by SQLite.
pub struct PersistentDht {
    /// SQLite connection.
    conn: Connection,
}

impl PersistentDht {
    /// Open a persistent DHT at the given file path.
    ///
    /// Creates the database and schema if it doesn't exist.
    pub fn open(path: &str) -> Result<Self, DhtError> {
        let conn = Connection::open(path).map_err(|e| DhtError::Persistence(e.to_string()))?;
        Self::init_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Create an in-memory persistent DHT (for testing).
    pub fn in_memory() -> Result<Self, DhtError> {
        let conn =
            Connection::open_in_memory().map_err(|e| DhtError::Persistence(e.to_string()))?;
        Self::init_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Initialize the database schema.
    fn init_schema(conn: &Connection) -> Result<(), DhtError> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS agent_records (
                agent_id BLOB PRIMARY KEY,
                record_data BLOB NOT NULL,
                capabilities TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_capabilities ON agent_records(capabilities);
            CREATE INDEX IF NOT EXISTS idx_expires_at ON agent_records(expires_at);
            PRAGMA journal_mode=WAL;
            "#,
        )
        .map_err(|e| DhtError::Persistence(e.to_string()))?;
        Ok(())
    }

    /// Get the current Unix timestamp.
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Store an agent record in the DHT.
    pub fn put(&mut self, record: &AgentRecord) -> Result<(), DhtError> {
        if !record.verify() {
            return Err(DhtError::VerificationFailed);
        }

        let record_bytes = record
            .to_bytes()
            .map_err(|e| DhtError::Persistence(e.to_string()))?;
        let caps = record.capabilities.join(",");
        let now = Self::now();

        self.conn
            .execute(
                "INSERT OR REPLACE INTO agent_records \
                 (agent_id, record_data, capabilities, expires_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![record.agent_id.as_slice(), record_bytes, caps, 0i64, now],
            )
            .map_err(|e| DhtError::Persistence(e.to_string()))?;
        Ok(())
    }

    /// Find all agents that advertise a given capability.
    pub fn get(&self, capability: &str) -> Result<Vec<AgentRecord>, DhtError> {
        let mut stmt = self
            .conn
            .prepare("SELECT record_data FROM agent_records WHERE capabilities LIKE ?1")
            .map_err(|e| DhtError::Persistence(e.to_string()))?;
        let pattern = format!("%{}%", capability);
        let rows = stmt
            .query_map(params![pattern], |row| {
                let data: Vec<u8> = row.get(0)?;
                AgentRecord::from_bytes(&data).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                    )
                })
            })
            .map_err(|e| DhtError::Persistence(e.to_string()))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| DhtError::Persistence(e.to_string()))?);
        }
        Ok(records)
    }

    /// Remove an agent from the DHT.
    pub fn remove_agent(&mut self, agent_id: &AgentId) -> Result<(), DhtError> {
        self.conn
            .execute(
                "DELETE FROM agent_records WHERE agent_id = ?1",
                params![agent_id.as_slice()],
            )
            .map_err(|e| DhtError::Persistence(e.to_string()))?;
        Ok(())
    }

    /// Evict expired records. Currently a no-op since the legacy
    /// AgentRecord doesn't have an expires_at field. When the v1
    /// AgentRecord is used, this will delete records where
    /// expires_at < now.
    pub fn evict_expired(&mut self) -> Result<(), DhtError> {
        // Legacy AgentRecord doesn't track expiry. This is a placeholder
        // for when v1 records with expires_at are used.
        Ok(())
    }

    /// Count the number of records in the DHT.
    pub fn count(&self) -> Result<usize, DhtError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM agent_records", [], |row| row.get(0))
            .map_err(|e| DhtError::Persistence(e.to_string()))?;
        Ok(count as usize)
    }

    /// List all capabilities in the DHT.
    pub fn list_capabilities(&self) -> Result<Vec<String>, DhtError> {
        let mut stmt = self
            .conn
            .prepare("SELECT capabilities FROM agent_records")
            .map_err(|e| DhtError::Persistence(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let caps: String = row.get(0)?;
                Ok(caps)
            })
            .map_err(|e| DhtError::Persistence(e.to_string()))?;

        let mut all_caps = std::collections::HashSet::new();
        for row in rows {
            let caps = row.map_err(|e| DhtError::Persistence(e.to_string()))?;
            for cap in caps.split(',') {
                if !cap.is_empty() {
                    all_caps.insert(cap.to_string());
                }
            }
        }
        Ok(all_caps.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_identity::AgentKeypair;

    fn make_record(caps: Vec<&str>) -> AgentRecord {
        let kp = AgentKeypair::generate();
        AgentRecord::new(
            &kp,
            caps.into_iter().map(String::from).collect(),
            vec!["quic://1.2.3.4:4433".into()],
        )
    }

    #[test]
    fn test_persistent_dht_insert_and_lookup() {
        let mut dht = PersistentDht::in_memory().unwrap();
        let record = make_record(vec!["inference", "translation"]);
        dht.put(&record).unwrap();

        let inference = dht.get("inference").unwrap();
        assert_eq!(inference.len(), 1);

        let translation = dht.get("translation").unwrap();
        assert_eq!(translation.len(), 1);

        let unknown = dht.get("unknown-cap").unwrap();
        assert_eq!(unknown.len(), 0);
    }

    #[test]
    fn test_persistent_dht_count() {
        let mut dht = PersistentDht::in_memory().unwrap();
        assert_eq!(dht.count().unwrap(), 0);

        let r1 = make_record(vec!["inference"]);
        dht.put(&r1).unwrap();
        assert_eq!(dht.count().unwrap(), 1);

        let r2 = make_record(vec!["translation"]);
        dht.put(&r2).unwrap();
        assert_eq!(dht.count().unwrap(), 2);
    }

    #[test]
    fn test_persistent_dht_remove_agent() {
        let mut dht = PersistentDht::in_memory().unwrap();
        let record = make_record(vec!["inference"]);
        let agent_id = record.agent_id;
        dht.put(&record).unwrap();
        assert_eq!(dht.get("inference").unwrap().len(), 1);

        dht.remove_agent(&agent_id).unwrap();
        assert_eq!(dht.get("inference").unwrap().len(), 0);
        assert_eq!(dht.count().unwrap(), 0);
    }

    #[test]
    fn test_persistent_dht_update_record() {
        let mut dht = PersistentDht::in_memory().unwrap();
        let kp = AgentKeypair::generate();
        let r1 = AgentRecord::new(&kp, vec!["inference".into()], vec![]);
        dht.put(&r1).unwrap();
        assert_eq!(dht.get("inference").unwrap().len(), 1);

        // Update with different capabilities (same agent_id).
        let r2 = AgentRecord::new_with_version(&kp, vec!["translation".into()], vec![], 2, 0);
        dht.put(&r2).unwrap();
        assert_eq!(dht.get("inference").unwrap().len(), 0);
        assert_eq!(dht.get("translation").unwrap().len(), 1);
        assert_eq!(dht.count().unwrap(), 1);
    }

    #[test]
    fn test_persistent_dht_list_capabilities() {
        let mut dht = PersistentDht::in_memory().unwrap();
        dht.put(&make_record(vec!["inference", "translation"]))
            .unwrap();
        dht.put(&make_record(vec!["inference", "coding"])).unwrap();

        let caps = dht.list_capabilities().unwrap();
        assert_eq!(caps.len(), 3); // inference, translation, coding
    }

    #[test]
    fn test_persistent_dht_rejects_invalid_record() {
        let mut dht = PersistentDht::in_memory().unwrap();
        let mut record = make_record(vec!["inference"]);
        record.capabilities.push("forged".into());
        assert!(dht.put(&record).is_err());
    }

    #[test]
    fn test_persistent_dht_survives_reopen() {
        let path = "/tmp/aafp_test_dht_persistent.sqlite";
        std::fs::remove_file(path).ok();

        // Insert a record.
        {
            let mut dht = PersistentDht::open(path).unwrap();
            let record = make_record(vec!["inference"]);
            dht.put(&record).unwrap();
            assert_eq!(dht.count().unwrap(), 1);
        }

        // Reopen and verify the record persists.
        {
            let dht = PersistentDht::open(path).unwrap();
            assert_eq!(dht.count().unwrap(), 1);
            let results = dht.get("inference").unwrap();
            assert_eq!(results.len(), 1);
        }

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_persistent_dht_empty() {
        let dht = PersistentDht::in_memory().unwrap();
        assert_eq!(dht.count().unwrap(), 0);
        assert_eq!(dht.get("anything").unwrap().len(), 0);
        assert_eq!(dht.list_capabilities().unwrap().len(), 0);
    }
}
