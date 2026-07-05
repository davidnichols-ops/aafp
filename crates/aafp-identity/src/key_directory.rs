//! Key directory: maps AgentId → AgentRecord (RFC 0011 §3).
//!
//! Provides lookup, publish, and verify operations for agent records.
//! Supports an in-memory backend (for testing) and a SQLite backend
//! (for persistence, following the PersistentDht pattern).

use crate::identity_v1::{AgentId, AgentRecord, IdentityError};
use aafp_cbor::{decode, encode};
use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme};
use rusqlite::{params, Connection};
use std::collections::HashMap;

/// Rate limit window: 1 publish per AgentId per hour (RFC 0011 §3.7).
const RATE_LIMIT_SECS: u64 = 3600;

/// Key directory errors.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    /// The AgentRecord signature is invalid.
    #[error("invalid record: {0}")]
    InvalidRecord(String),
    /// Rate limited — too many publishes.
    #[error("rate limited: publish too frequent for this agent_id")]
    RateLimited,
    /// SQLite error.
    #[error("persistence error: {0}")]
    Persistence(String),
    /// CBOR error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] aafp_cbor::CborError),
    /// Identity error.
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    /// Record not found.
    #[error("record not found")]
    NotFound,
}

/// In-memory key directory (HashMap backend).
///
/// Suitable for testing and ephemeral use. For persistence, use
/// [`PersistentKeyDirectory`].
pub struct KeyDirectory {
    records: HashMap<AgentId, AgentRecord>,
    /// Last publish timestamp per AgentId (for rate limiting).
    last_publish: HashMap<AgentId, u64>,
    /// Optional directory keypair for signing responses.
    directory_key: Option<(MlDsa65PublicKey, MlDsa65SecretKey)>,
}

impl KeyDirectory {
    /// Create a new empty in-memory key directory.
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            last_publish: HashMap::new(),
            directory_key: None,
        }
    }

    /// Set the directory's own keypair for signing responses.
    pub fn with_directory_key(
        mut self,
        public_key: MlDsa65PublicKey,
        secret_key: MlDsa65SecretKey,
    ) -> Self {
        self.directory_key = Some((public_key, secret_key));
        self
    }

    /// Look up an AgentRecord by AgentId.
    pub fn lookup(&self, agent_id: &AgentId) -> Option<&AgentRecord> {
        self.records.get(agent_id)
    }

    /// Publish an AgentRecord to the directory.
    ///
    /// Verifies the record signature and rate-limits to 1 publish per
    /// AgentId per hour (RFC 0011 §3.7).
    pub fn publish(&mut self, record: AgentRecord, now: u64) -> Result<(), DirectoryError> {
        // Verify the record signature and fields.
        record
            .verify(now)
            .map_err(|e| DirectoryError::InvalidRecord(e.to_string()))?;

        // Rate limit: 1 publish per AgentId per hour.
        if let Some(&last) = self.last_publish.get(&record.agent_id) {
            if now.saturating_sub(last) < RATE_LIMIT_SECS {
                return Err(DirectoryError::RateLimited);
            }
        }

        // Check monotonic version: reject older versions.
        if let Some(existing) = self.records.get(&record.agent_id) {
            if record.record_version < existing.record_version {
                return Err(DirectoryError::InvalidRecord(
                    "record_version is older than existing".to_string(),
                ));
            }
        }

        self.last_publish.insert(record.agent_id, now);
        self.records.insert(record.agent_id, record);
        Ok(())
    }

    /// Verify that a record matches the directory's stored record for
    /// the given AgentId.
    pub fn verify(&self, agent_id: &AgentId, record: &AgentRecord, now: u64) -> bool {
        match self.records.get(agent_id) {
            Some(stored) => {
                // Compare key fields
                stored.agent_id == record.agent_id
                    && stored.public_key == record.public_key
                    && stored.signature == record.signature
                    && record.verify(now).is_ok()
            }
            None => false,
        }
    }

    /// Sign a record with the directory's key (if configured).
    /// Returns the signature bytes, or None if no directory key.
    pub fn sign_record(&self, record_bytes: &[u8]) -> Option<Vec<u8>> {
        self.directory_key.as_ref().map(|(_, sk)| {
            let sig = MlDsa65::sign(sk, record_bytes);
            sig.0
        })
    }

    /// Verify a directory signature on a record.
    pub fn verify_directory_signature(
        &self,
        record_bytes: &[u8],
        signature: &[u8],
        directory_public_key: &MlDsa65PublicKey,
    ) -> bool {
        match MlDsa65Signature::from_bytes(signature) {
            Ok(sig) => MlDsa65::verify(directory_public_key, record_bytes, &sig),
            Err(_) => false,
        }
    }

    /// Get the number of records in the directory.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if the directory is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Evict expired records.
    pub fn evict_expired(&mut self, now: u64) {
        self.records.retain(|_, r| !r.is_expired(now));
    }
}

impl Default for KeyDirectory {
    fn default() -> Self {
        Self::new()
    }
}

/// Persistent key directory backed by SQLite (RFC 0011 §3).
///
/// Follows the PersistentDht pattern for SQLite storage.
pub struct PersistentKeyDirectory {
    conn: Connection,
    /// Optional directory keypair for signing responses.
    directory_key: Option<(MlDsa65PublicKey, MlDsa65SecretKey)>,
}

impl PersistentKeyDirectory {
    /// Open a persistent key directory at the given file path.
    ///
    /// Creates the database and schema if it doesn't exist.
    pub fn open(path: &str) -> Result<Self, DirectoryError> {
        let conn =
            Connection::open(path).map_err(|e| DirectoryError::Persistence(e.to_string()))?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn,
            directory_key: None,
        })
    }

    /// Create an in-memory persistent key directory (for testing).
    pub fn in_memory() -> Result<Self, DirectoryError> {
        let conn =
            Connection::open_in_memory().map_err(|e| DirectoryError::Persistence(e.to_string()))?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn,
            directory_key: None,
        })
    }

    /// Set the directory's own keypair for signing responses.
    pub fn set_directory_key(
        &mut self,
        public_key: MlDsa65PublicKey,
        secret_key: MlDsa65SecretKey,
    ) {
        self.directory_key = Some((public_key, secret_key));
    }

    /// Initialize the database schema.
    fn init_schema(conn: &Connection) -> Result<(), DirectoryError> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS key_directory (
                agent_id BLOB PRIMARY KEY,
                record_cbor BLOB NOT NULL,
                record_version INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_publish INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kd_expires ON key_directory(expires_at);
            PRAGMA journal_mode=WAL;
            "#,
        )
        .map_err(|e| DirectoryError::Persistence(e.to_string()))?;
        Ok(())
    }

    /// Look up an AgentRecord by AgentId.
    pub fn lookup(&self, agent_id: &AgentId) -> Result<Option<AgentRecord>, DirectoryError> {
        let mut stmt = self
            .conn
            .prepare("SELECT record_cbor FROM key_directory WHERE agent_id = ?1")
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?;

        let mut rows = stmt
            .query(params![agent_id.0.as_slice()])
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?;

        match rows
            .next()
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?
        {
            Some(row) => {
                let data: Vec<u8> = row
                    .get(0)
                    .map_err(|e| DirectoryError::Persistence(e.to_string()))?;
                let (val, _) = decode(&data)?;
                let record = AgentRecord::from_cbor(&val)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Publish an AgentRecord to the directory.
    ///
    /// Verifies the record signature and rate-limits to 1 publish per
    /// AgentId per hour (RFC 0011 §3.7).
    pub fn publish(&mut self, record: &AgentRecord, now: u64) -> Result<(), DirectoryError> {
        // Verify the record signature and fields.
        record
            .verify(now)
            .map_err(|e| DirectoryError::InvalidRecord(e.to_string()))?;

        // Check rate limit.
        let mut stmt = self
            .conn
            .prepare("SELECT last_publish FROM key_directory WHERE agent_id = ?1")
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?;

        let mut rows = stmt
            .query(params![record.agent_id.0.as_slice()])
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?;

        if let Some(row) = rows
            .next()
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?
        {
            let last: i64 = row
                .get(0)
                .map_err(|e| DirectoryError::Persistence(e.to_string()))?;
            let last = last as u64;
            if now.saturating_sub(last) < RATE_LIMIT_SECS {
                return Err(DirectoryError::RateLimited);
            }
        }

        // Check monotonic version.
        if let Some(row) = rows
            .next()
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?
        {
            let _ = row;
        }
        // Re-query for version check
        let mut stmt2 = self
            .conn
            .prepare("SELECT record_version FROM key_directory WHERE agent_id = ?1")
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?;
        let mut rows2 = stmt2
            .query(params![record.agent_id.0.as_slice()])
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?;
        if let Some(row) = rows2
            .next()
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?
        {
            let existing_version: i64 = row
                .get(0)
                .map_err(|e| DirectoryError::Persistence(e.to_string()))?;
            if (record.record_version as i64) < existing_version {
                return Err(DirectoryError::InvalidRecord(
                    "record_version is older than existing".to_string(),
                ));
            }
        }

        // Encode and store.
        let cbor = record.to_cbor();
        let cbor_bytes = encode(&cbor)?;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO key_directory \
                 (agent_id, record_cbor, record_version, expires_at, last_publish) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    record.agent_id.0.as_slice(),
                    cbor_bytes,
                    record.record_version as i64,
                    record.expires_at as i64,
                    now as i64,
                ],
            )
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?;
        Ok(())
    }

    /// Verify that a record matches the directory's stored record.
    pub fn verify(
        &self,
        agent_id: &AgentId,
        record: &AgentRecord,
        now: u64,
    ) -> Result<bool, DirectoryError> {
        match self.lookup(agent_id)? {
            Some(stored) => Ok(stored.agent_id == record.agent_id
                && stored.public_key == record.public_key
                && stored.signature == record.signature
                && record.verify(now).is_ok()),
            None => Ok(false),
        }
    }

    /// Sign a record with the directory's key (if configured).
    pub fn sign_record(&self, record_bytes: &[u8]) -> Option<Vec<u8>> {
        self.directory_key.as_ref().map(|(_, sk)| {
            let sig = MlDsa65::sign(sk, record_bytes);
            sig.0
        })
    }

    /// Get the directory's public key (if configured).
    pub fn directory_public_key(&self) -> Option<&MlDsa65PublicKey> {
        self.directory_key.as_ref().map(|(pk, _)| pk)
    }

    /// Evict expired records.
    pub fn evict_expired(&mut self, now: u64) -> Result<usize, DirectoryError> {
        let count = self
            .conn
            .execute(
                "DELETE FROM key_directory WHERE expires_at < ?1",
                params![now as i64],
            )
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?;
        Ok(count)
    }

    /// Get the number of records in the directory.
    pub fn len(&self) -> Result<usize, DirectoryError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM key_directory", [], |row| row.get(0))
            .map_err(|e| DirectoryError::Persistence(e.to_string()))?;
        Ok(count as usize)
    }

    /// Check if the directory is empty.
    pub fn is_empty(&self) -> Result<bool, DirectoryError> {
        Ok(self.len()? == 0)
    }
}

/// Key directory client.
///
/// Connects to a directory server, queries records, and publishes
/// own records. The actual network transport is handled by the
/// caller; this type provides the request/response encoding and
/// verification logic.
pub struct KeyDirectoryClient {
    /// Trusted directory public key (for verifying signed responses).
    directory_public_key: Option<MlDsa65PublicKey>,
}

impl KeyDirectoryClient {
    /// Create a new key directory client.
    pub fn new() -> Self {
        Self {
            directory_public_key: None,
        }
    }

    /// Set the trusted directory public key for verifying signed responses.
    pub fn with_directory_public_key(mut self, pk: MlDsa65PublicKey) -> Self {
        self.directory_public_key = Some(pk);
        self
    }

    /// Encode a lookup request (aafp.directory.lookup).
    pub fn encode_lookup_request(agent_id: &AgentId) -> Vec<u8> {
        let cbor = aafp_cbor::int_map(vec![(1, aafp_cbor::Value::ByteString(agent_id.0.to_vec()))]);
        encode(&cbor).unwrap_or_default()
    }

    /// Decode a lookup response.
    ///
    /// Returns (record, directory_signature) where either may be None.
    pub fn decode_lookup_response(
        &self,
        data: &[u8],
        now: u64,
    ) -> Result<Option<AgentRecord>, DirectoryError> {
        let (val, _) = decode(data)?;
        let record_bytes = match aafp_cbor::int_map_get(&val, 1) {
            Some(aafp_cbor::Value::ByteString(b)) => b.clone(),
            Some(aafp_cbor::Value::Null) | None => return Ok(None),
            _ => return Err(DirectoryError::InvalidRecord("invalid record field".into())),
        };

        let (record_cbor, _) = decode(&record_bytes)?;
        let record = AgentRecord::from_cbor(&record_cbor)?;
        record
            .verify(now)
            .map_err(|e| DirectoryError::InvalidRecord(e.to_string()))?;

        // Verify directory signature if present and we have the key.
        if let Some(dir_pk) = &self.directory_public_key {
            if let Some(aafp_cbor::Value::ByteString(sig)) = aafp_cbor::int_map_get(&val, 2) {
                let sig_obj = MlDsa65Signature::from_bytes(sig).map_err(|_| {
                    DirectoryError::InvalidRecord("invalid directory signature".into())
                })?;
                if !MlDsa65::verify(dir_pk, &record_bytes, &sig_obj) {
                    return Err(DirectoryError::InvalidRecord(
                        "directory signature verification failed".into(),
                    ));
                }
            }
        }

        Ok(Some(record))
    }

    /// Encode a publish request (aafp.directory.publish).
    pub fn encode_publish_request(record: &AgentRecord) -> Vec<u8> {
        let cbor = record.to_cbor();
        let cbor_bytes = encode(&cbor).unwrap_or_default();
        let request = aafp_cbor::int_map(vec![(1, aafp_cbor::Value::ByteString(cbor_bytes))]);
        encode(&request).unwrap_or_default()
    }

    /// Decode a publish response.
    pub fn decode_publish_response(data: &[u8]) -> Result<(u64, String), DirectoryError> {
        let (val, _) = decode(data)?;
        let status = match aafp_cbor::int_map_get(&val, 1) {
            Some(aafp_cbor::Value::Unsigned(n)) => *n,
            _ => return Err(DirectoryError::InvalidRecord("invalid status field".into())),
        };
        let message = match aafp_cbor::int_map_get(&val, 2) {
            Some(aafp_cbor::Value::TextString(s)) => s.clone(),
            _ => String::new(),
        };
        Ok((status, message))
    }
}

impl Default for KeyDirectoryClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_v1::{CapabilityDescriptor, KEY_ALG_ML_DSA_65};
    use aafp_crypto::MlDsa65;

    fn make_record(now: u64) -> (AgentRecord, MlDsa65SecretKey) {
        let (pk, sk) = MlDsa65::keypair();
        let mut record = AgentRecord::new(
            &pk.0,
            vec![CapabilityDescriptor::new("inference")],
            vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
            now,
            now + 86400,
            KEY_ALG_ML_DSA_65,
        );
        record.sign(&sk);
        (record, sk)
    }

    #[test]
    fn test_in_memory_publish_and_lookup() {
        let now = 1700000000u64;
        let mut dir = KeyDirectory::new();
        let (record, _) = make_record(now);

        dir.publish(record.clone(), now).unwrap();
        assert_eq!(dir.len(), 1);

        let looked_up = dir.lookup(&record.agent_id).unwrap();
        assert_eq!(looked_up.agent_id, record.agent_id);
        assert_eq!(looked_up.public_key, record.public_key);
    }

    #[test]
    fn test_in_memory_verify() {
        let now = 1700000000u64;
        let mut dir = KeyDirectory::new();
        let (record, _) = make_record(now);

        dir.publish(record.clone(), now).unwrap();
        assert!(dir.verify(&record.agent_id, &record, now));
    }

    #[test]
    fn test_rejects_invalid_signature() {
        let now = 1700000000u64;
        let mut dir = KeyDirectory::new();
        let (mut record, _) = make_record(now);

        // Tamper with signature
        record.signature[0] ^= 0xFF;

        let result = dir.publish(record, now);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DirectoryError::InvalidRecord(_)
        ));
    }

    #[test]
    fn test_rejects_bad_agent_id() {
        let now = 1700000000u64;
        let mut dir = KeyDirectory::new();
        let (mut record, _) = make_record(now);

        // Tamper with agent_id
        record.agent_id = AgentId([0xFFu8; 32]);

        let result = dir.publish(record, now);
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limiting() {
        let now = 1700000000u64;
        let mut dir = KeyDirectory::new();
        let (record, _) = make_record(now);

        // First publish succeeds
        dir.publish(record.clone(), now).unwrap();

        // Second publish within 1 hour fails
        let result = dir.publish(record.clone(), now + 100);
        assert!(matches!(result.unwrap_err(), DirectoryError::RateLimited));

        // Publish after 1 hour succeeds
        dir.publish(record, now + RATE_LIMIT_SECS + 1).unwrap();
    }

    #[test]
    fn test_persistent_publish_and_lookup() {
        let now = 1700000000u64;
        let mut dir = PersistentKeyDirectory::in_memory().unwrap();
        let (record, _) = make_record(now);

        dir.publish(&record, now).unwrap();
        assert_eq!(dir.len().unwrap(), 1);

        let looked_up = dir.lookup(&record.agent_id).unwrap().unwrap();
        assert_eq!(looked_up.agent_id, record.agent_id);
        assert_eq!(looked_up.public_key, record.public_key);
    }

    #[test]
    fn test_persistent_verify() {
        let now = 1700000000u64;
        let mut dir = PersistentKeyDirectory::in_memory().unwrap();
        let (record, _) = make_record(now);

        dir.publish(&record, now).unwrap();
        assert!(dir.verify(&record.agent_id, &record, now).unwrap());
    }

    #[test]
    fn test_persistent_rate_limiting() {
        let now = 1700000000u64;
        let mut dir = PersistentKeyDirectory::in_memory().unwrap();
        let (record, _) = make_record(now);

        dir.publish(&record, now).unwrap();
        let result = dir.publish(&record, now + 100);
        assert!(matches!(result.unwrap_err(), DirectoryError::RateLimited));

        dir.publish(&record, now + RATE_LIMIT_SECS + 1).unwrap();
    }

    #[test]
    fn test_persistent_evict_expired() {
        let now = 1700000000u64;
        let mut dir = PersistentKeyDirectory::in_memory().unwrap();
        let (record, _) = make_record(now);

        dir.publish(&record, now).unwrap();
        assert_eq!(dir.len().unwrap(), 1);

        // Evict after expiry
        let evicted = dir.evict_expired(now + 86400 + 1).unwrap();
        assert_eq!(evicted, 1);
        assert_eq!(dir.len().unwrap(), 0);
    }

    #[test]
    fn test_directory_signs_responses() {
        let now = 1700000000u64;
        let (dir_pk, dir_sk) = MlDsa65::keypair();
        let mut dir =
            KeyDirectory::new().with_directory_key(MlDsa65PublicKey(dir_pk.0.clone()), dir_sk);
        let (record, _) = make_record(now);
        dir.publish(record.clone(), now).unwrap();

        // Sign the record bytes
        let record_bytes = encode(&record.to_cbor()).unwrap();
        let sig = dir.sign_record(&record_bytes).unwrap();
        assert!(!sig.is_empty());

        // Verify the signature
        assert!(dir.verify_directory_signature(&record_bytes, &sig, &dir_pk));
    }

    #[test]
    fn test_client_lookup_encode_decode() {
        let now = 1700000000u64;
        let (record, _) = make_record(now);
        let client = KeyDirectoryClient::new();

        // Encode lookup request
        let req = KeyDirectoryClient::encode_lookup_request(&record.agent_id);
        assert!(!req.is_empty());

        // Decode the request to verify
        let (val, _) = decode(&req).unwrap();
        let agent_id_bytes = match aafp_cbor::int_map_get(&val, 1) {
            Some(aafp_cbor::Value::ByteString(b)) => b.clone(),
            _ => panic!("expected bstr"),
        };
        assert_eq!(agent_id_bytes, record.agent_id.0.to_vec());

        // Encode a lookup response with the record
        let record_cbor = record.to_cbor();
        let record_bytes = encode(&record_cbor).unwrap();
        let response = aafp_cbor::int_map(vec![
            (1, aafp_cbor::Value::ByteString(record_bytes)),
            (2, aafp_cbor::Value::Null),
        ]);
        let response_bytes = encode(&response).unwrap();

        // Decode the response
        let decoded = client.decode_lookup_response(&response_bytes, now).unwrap();
        let decoded_record = decoded.unwrap();
        assert_eq!(decoded_record.agent_id, record.agent_id);
    }

    #[test]
    fn test_client_publish_encode_decode() {
        let now = 1700000000u64;
        let (record, _) = make_record(now);

        let req = KeyDirectoryClient::encode_publish_request(&record);
        assert!(!req.is_empty());

        // Encode a publish response
        let response = aafp_cbor::int_map(vec![
            (1, aafp_cbor::Value::Unsigned(0)),
            (2, aafp_cbor::Value::TextString("success".to_string())),
        ]);
        let response_bytes = encode(&response).unwrap();

        let (status, message) =
            KeyDirectoryClient::decode_publish_response(&response_bytes).unwrap();
        assert_eq!(status, 0);
        assert_eq!(message, "success");
    }

    #[test]
    fn test_lookup_not_found() {
        let dir = KeyDirectory::new();
        let agent_id = AgentId([0xAAu8; 32]);
        assert!(dir.lookup(&agent_id).is_none());
    }

    #[test]
    fn test_persistent_lookup_not_found() {
        let dir = PersistentKeyDirectory::in_memory().unwrap();
        let agent_id = AgentId([0xAAu8; 32]);
        assert!(dir.lookup(&agent_id).unwrap().is_none());
    }

    #[test]
    fn test_client_lookup_response_not_found() {
        let client = KeyDirectoryClient::new();
        let response = aafp_cbor::int_map(vec![
            (1, aafp_cbor::Value::Null),
            (2, aafp_cbor::Value::Null),
        ]);
        let response_bytes = encode(&response).unwrap();
        let result = client
            .decode_lookup_response(&response_bytes, 1700000000)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_monotonic_version_rejects_older() {
        let now = 1700000000u64;
        let mut dir = KeyDirectory::new();
        let (mut record, _) = make_record(now);
        record.record_version = 5;
        // Re-sign because we changed the version
        let (pk, sk) = MlDsa65::keypair();
        record.public_key = pk.0.clone();
        record.agent_id = AgentId::from_public_key(&pk.0);
        record.sign(&sk);

        dir.publish(record.clone(), now).unwrap();

        // Try to publish an older version
        let mut old_record = record.clone();
        old_record.record_version = 3;
        let result = dir.publish(old_record, now + RATE_LIMIT_SECS + 1);
        assert!(result.is_err());
    }
}
