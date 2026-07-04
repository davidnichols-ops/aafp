//! Revocation: CRL-based identity revocation (RFC-0003 amendment).
//!
//! Allows revoking compromised agent identities via signed revocation lists.
//! A CRL (Certificate Revocation List) is a CBOR-encoded signed list of
//! revoked AgentIds that peers check before accepting a connection.

use crate::identity_v1::AgentId;
use aafp_cbor::{decode, encode, int_map, int_map_get, CborError, Value};
use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, SignatureScheme};
use std::collections::HashSet;
use thiserror::Error;

/// Domain separator for revocation signatures.
const REVOCATION_DOMAIN_SEPARATOR: &[u8] = b"AAFP-REVOCATION-V1";

/// Default CRL TTL in seconds (1 hour).
pub const DEFAULT_CRL_TTL_SECS: u64 = 3600;

/// Revocation errors.
#[derive(Debug, Error)]
pub enum RevocationError {
    /// CBOR encoding/decoding error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    /// CRL has expired.
    #[error("CRL expired")]
    Expired,
    /// Missing field in CBOR data.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// Invalid field value.
    #[error("invalid field {field}: {message}")]
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Error message.
        message: String,
    },
}

/// A single revocation entry (RFC-0003 amendment §Wire Format).
///
/// Signed statement that an AgentId has been revoked.
#[derive(Clone, Debug)]
pub struct RevocationEntry {
    /// The revoked AgentId (32 bytes).
    pub agent_id: AgentId,
    /// Unix timestamp when the revocation occurred.
    pub revoked_at: u64,
    /// Optional reason: "compromised", "rotated", etc.
    pub reason: Option<String>,
    /// AgentId of the revoking key (who signed this entry).
    pub revoking_key_id: AgentId,
    /// ML-DSA-65 signature over fields 1-4.
    pub signature: Vec<u8>,
}

impl RevocationEntry {
    /// Create and sign a revocation entry.
    ///
    /// The `secret_key` is used to sign the revocation. The
    /// `revoking_key_id` should be the AgentId derived from the
    /// corresponding public key.
    pub fn new(
        agent_id: AgentId,
        revoked_at: u64,
        reason: Option<String>,
        revoking_key_id: AgentId,
        secret_key: &MlDsa65SecretKey,
    ) -> Self {
        let mut entry = Self {
            agent_id,
            revoked_at,
            reason,
            revoking_key_id,
            signature: Vec::new(),
        };
        let sig_input = entry.signature_input();
        let sig = MlDsa65::sign(secret_key, &sig_input);
        entry.signature = sig.0;
        entry
    }

    /// Compute the signature input (fields 1-4 with domain separator).
    fn signature_input(&self) -> Vec<u8> {
        let cbor = self.to_cbor_without_sig();
        let cbor_bytes = encode(&cbor).unwrap_or_default();
        let mut input = Vec::with_capacity(REVOCATION_DOMAIN_SEPARATOR.len() + cbor_bytes.len());
        input.extend_from_slice(REVOCATION_DOMAIN_SEPARATOR);
        input.extend_from_slice(&cbor_bytes);
        input
    }

    /// Encode to CBOR without the signature field (for signing).
    fn to_cbor_without_sig(&self) -> Value {
        int_map(vec![
            (1, Value::ByteString(self.agent_id.0.to_vec())),
            (2, Value::Unsigned(self.revoked_at)),
            (
                3,
                self.reason
                    .as_ref()
                    .map(|r| Value::TextString(r.clone()))
                    .unwrap_or(Value::Null),
            ),
            (4, Value::ByteString(self.revoking_key_id.0.to_vec())),
        ])
    }

    /// Encode to CBOR (with signature).
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::ByteString(self.agent_id.0.to_vec())),
            (2, Value::Unsigned(self.revoked_at)),
            (
                3,
                self.reason
                    .as_ref()
                    .map(|r| Value::TextString(r.clone()))
                    .unwrap_or(Value::Null),
            ),
            (4, Value::ByteString(self.revoking_key_id.0.to_vec())),
            (5, Value::ByteString(self.signature.clone())),
        ])
    }

    /// Decode from CBOR.
    pub fn from_cbor(val: &Value) -> Result<Self, RevocationError> {
        let agent_id = match int_map_get(val, 1) {
            Some(Value::ByteString(b)) => {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    AgentId(arr)
                } else {
                    return Err(RevocationError::InvalidField {
                        field: "agent_id",
                        message: "must be 32 bytes".to_string(),
                    });
                }
            }
            _ => return Err(RevocationError::MissingField("agent_id")),
        };

        let revoked_at = match int_map_get(val, 2) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RevocationError::MissingField("revoked_at")),
        };

        let reason = match int_map_get(val, 3) {
            Some(Value::TextString(s)) => Some(s.clone()),
            Some(Value::Null) | None => None,
            _ => None,
        };

        let revoking_key_id = match int_map_get(val, 4) {
            Some(Value::ByteString(b)) => {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    AgentId(arr)
                } else {
                    return Err(RevocationError::InvalidField {
                        field: "revoking_key_id",
                        message: "must be 32 bytes".to_string(),
                    });
                }
            }
            _ => return Err(RevocationError::MissingField("revoking_key_id")),
        };

        let signature = match int_map_get(val, 5) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => return Err(RevocationError::MissingField("signature")),
        };

        Ok(Self {
            agent_id,
            revoked_at,
            reason,
            revoking_key_id,
            signature,
        })
    }

    /// Verify the revocation entry's signature.
    ///
    /// `public_key` is the public key corresponding to the revoking key.
    pub fn verify(&self, public_key: &MlDsa65PublicKey) -> bool {
        let sig_input = self.signature_input();
        let sig = aafp_crypto::MlDsa65Signature(self.signature.clone());
        MlDsa65::verify(public_key, &sig_input, &sig)
    }
}

/// A Certificate Revocation List (RFC-0003 amendment).
#[derive(Clone, Debug)]
pub struct RevocationList {
    /// Revocation entries in this CRL.
    pub entries: Vec<RevocationEntry>,
    /// Unix timestamp when this CRL was generated.
    pub generated_at: u64,
    /// Unix timestamp when this CRL expires.
    pub expires_at: u64,
}

impl RevocationList {
    /// Create an empty CRL with the given TTL.
    pub fn new(now: u64, ttl_seconds: u64) -> Self {
        Self {
            entries: Vec::new(),
            generated_at: now,
            expires_at: now + ttl_seconds,
        }
    }

    /// Add a revocation entry (signed by the revoking key).
    pub fn revoke(
        &mut self,
        agent_id: AgentId,
        revoked_at: u64,
        reason: Option<String>,
        revoking_key_id: AgentId,
        secret_key: &MlDsa65SecretKey,
    ) {
        let entry = RevocationEntry::new(agent_id, revoked_at, reason, revoking_key_id, secret_key);
        self.entries.push(entry);
    }

    /// Check if an AgentId is revoked.
    pub fn is_revoked(&self, agent_id: &AgentId) -> bool {
        self.entries.iter().any(|e| &e.agent_id == agent_id)
    }

    /// Check if this CRL has expired.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Get all revoked AgentIds.
    pub fn revoked_ids(&self) -> Vec<AgentId> {
        self.entries.iter().map(|e| e.agent_id).collect()
    }

    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (
                1,
                Value::Array(self.entries.iter().map(|e| e.to_cbor()).collect()),
            ),
            (2, Value::Unsigned(self.generated_at)),
            (3, Value::Unsigned(self.expires_at)),
        ])
    }

    /// Encode to CBOR bytes.
    pub fn encode(&self) -> Result<Vec<u8>, RevocationError> {
        encode(&self.to_cbor()).map_err(RevocationError::Cbor)
    }

    /// Decode from CBOR.
    pub fn from_cbor(val: &Value) -> Result<Self, RevocationError> {
        let entries = match int_map_get(val, 1) {
            Some(Value::Array(arr)) => {
                let mut entries = Vec::new();
                for v in arr {
                    entries.push(RevocationEntry::from_cbor(v)?);
                }
                entries
            }
            _ => return Err(RevocationError::MissingField("entries")),
        };

        let generated_at = match int_map_get(val, 2) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RevocationError::MissingField("generated_at")),
        };

        let expires_at = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RevocationError::MissingField("expires_at")),
        };

        Ok(Self {
            entries,
            generated_at,
            expires_at,
        })
    }

    /// Decode from CBOR bytes.
    pub fn decode(data: &[u8]) -> Result<Self, RevocationError> {
        let (val, _) = decode(data).map_err(RevocationError::Cbor)?;
        Self::from_cbor(&val)
    }
}

/// Local store of revocation lists (RFC-0003 amendment).
///
/// Maintains a merged view of all known CRLs for fast lookup.
pub struct RevocationStore {
    /// Merged set of all revoked AgentIds.
    revoked: HashSet<AgentId>,
    /// Known CRLs.
    crls: Vec<RevocationList>,
}

impl RevocationStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            revoked: HashSet::new(),
            crls: Vec::new(),
        }
    }

    /// Add a CRL to the store.
    ///
    /// All AgentIds from the CRL are added to the revoked set.
    pub fn add_crl(&mut self, crl: RevocationList) {
        for entry in &crl.entries {
            self.revoked.insert(entry.agent_id);
        }
        self.crls.push(crl);
    }

    /// Check if an AgentId is revoked.
    pub fn is_revoked(&self, agent_id: &AgentId) -> bool {
        self.revoked.contains(agent_id)
    }

    /// Evict expired CRLs and rebuild the revoked set.
    pub fn evict_expired(&mut self, now: u64) {
        self.crls.retain(|crl| !crl.is_expired(now));
        self.revoked = self
            .crls
            .iter()
            .flat_map(|crl| crl.entries.iter().map(|e| e.agent_id))
            .collect();
    }

    /// Get the number of revoked AgentIds.
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    /// Get the number of stored CRLs.
    pub fn crl_count(&self) -> usize {
        self.crls.len()
    }

    /// Get all revoked AgentIds.
    pub fn revoked_ids(&self) -> Vec<AgentId> {
        self.revoked.iter().cloned().collect()
    }
}

impl Default for RevocationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keypair() -> (MlDsa65PublicKey, MlDsa65SecretKey, AgentId) {
        let (pk, sk) = MlDsa65::keypair();
        let agent_id = AgentId::from_public_key(&pk.0);
        (pk, sk, agent_id)
    }

    #[test]
    fn test_revoke_and_check() {
        let (pk, sk, revoking_id) = make_keypair();
        let target_id = AgentId([0xAA; 32]);
        let now = 1700000000u64;

        let mut crl = RevocationList::new(now, DEFAULT_CRL_TTL_SECS);
        crl.revoke(
            target_id.clone(),
            now,
            Some("compromised".to_string()),
            revoking_id,
            &sk,
        );

        assert!(crl.is_revoked(&target_id));
        assert_eq!(crl.entries.len(), 1);

        // Verify signature
        assert!(crl.entries[0].verify(&pk));
    }

    #[test]
    fn test_crl_not_revoked() {
        let (_pk, sk, revoking_id) = make_keypair();
        let target_id = AgentId([0xAA; 32]);
        let other_id = AgentId([0xBB; 32]);
        let now = 1700000000u64;

        let mut crl = RevocationList::new(now, DEFAULT_CRL_TTL_SECS);
        crl.revoke(target_id.clone(), now, None, revoking_id, &sk);

        assert!(crl.is_revoked(&target_id));
        assert!(!crl.is_revoked(&other_id));
    }

    #[test]
    fn test_crl_cbor_roundtrip() {
        let (_pk, sk, revoking_id) = make_keypair();
        let target_id = AgentId([0xAA; 32]);
        let now = 1700000000u64;

        let mut crl = RevocationList::new(now, DEFAULT_CRL_TTL_SECS);
        crl.revoke(
            target_id.clone(),
            now,
            Some("compromised".to_string()),
            revoking_id,
            &sk,
        );

        let encoded = crl.encode().unwrap();
        let decoded = RevocationList::decode(&encoded).unwrap();

        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].agent_id, target_id);
        assert_eq!(decoded.entries[0].reason, Some("compromised".to_string()));
        assert_eq!(decoded.generated_at, crl.generated_at);
        assert_eq!(decoded.expires_at, crl.expires_at);
    }

    #[test]
    fn test_revocation_entry_cbor_roundtrip() {
        let (pk, sk, revoking_id) = make_keypair();
        let target_id = AgentId([0xCC; 32]);
        let now = 1700000000u64;

        let entry = RevocationEntry::new(
            target_id.clone(),
            now,
            Some("rotated".to_string()),
            revoking_id.clone(),
            &sk,
        );

        let cbor = entry.to_cbor();
        let decoded = RevocationEntry::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.agent_id, target_id);
        assert_eq!(decoded.revoked_at, now);
        assert_eq!(decoded.reason, Some("rotated".to_string()));
        assert_eq!(decoded.revoking_key_id, revoking_id);
        assert_eq!(decoded.signature, entry.signature);

        // Verify decoded signature
        assert!(decoded.verify(&pk));
    }

    #[test]
    fn test_revocation_store() {
        let (_pk, sk, revoking_id) = make_keypair();
        let target1 = AgentId([0xAA; 32]);
        let target2 = AgentId([0xBB; 32]);
        let now = 1700000000u64;

        let mut crl1 = RevocationList::new(now, DEFAULT_CRL_TTL_SECS);
        crl1.revoke(target1.clone(), now, None, revoking_id.clone(), &sk);

        let mut crl2 = RevocationList::new(now, DEFAULT_CRL_TTL_SECS);
        crl2.revoke(
            target2.clone(),
            now,
            Some("compromised".to_string()),
            revoking_id,
            &sk,
        );

        let mut store = RevocationStore::new();
        store.add_crl(crl1);
        store.add_crl(crl2);

        assert!(store.is_revoked(&target1));
        assert!(store.is_revoked(&target2));
        assert!(!store.is_revoked(&AgentId([0xFF; 32])));
        assert_eq!(store.revoked_count(), 2);
        assert_eq!(store.crl_count(), 2);
    }

    #[test]
    fn test_store_evict_expired() {
        let (_pk, sk, revoking_id) = make_keypair();
        let target = AgentId([0xAA; 32]);
        let now = 1700000000u64;

        let mut crl = RevocationList::new(now, 100); // 100 second TTL
        crl.revoke(target.clone(), now, None, revoking_id, &sk);

        let mut store = RevocationStore::new();
        store.add_crl(crl);

        assert!(store.is_revoked(&target));

        // Evict after TTL
        store.evict_expired(now + 200);
        assert!(!store.is_revoked(&target));
        assert_eq!(store.crl_count(), 0);
    }

    #[test]
    fn test_crl_expired() {
        let now = 1700000000u64;
        let crl = RevocationList::new(now, 100);
        assert!(!crl.is_expired(now));
        assert!(!crl.is_expired(now + 99));
        assert!(crl.is_expired(now + 100));
        assert!(crl.is_expired(now + 200));
    }

    #[test]
    fn test_signature_verification_rejects_wrong_key() {
        let (_pk1, _sk1, _revoking_id1) = make_keypair();
        let (pk2, sk2, revoking_id2) = make_keypair();
        let target_id = AgentId([0xDD; 32]);
        let now = 1700000000u64;

        // Sign with sk2, verify with pk2 — should pass
        let entry = RevocationEntry::new(target_id, now, None, revoking_id2, &sk2);
        assert!(entry.verify(&pk2));

        // Try to verify with a different key — should fail
        let (pk3, _sk3, _) = make_keypair();
        assert!(!entry.verify(&pk3));
    }

    #[test]
    fn test_empty_crl() {
        let now = 1700000000u64;
        let crl = RevocationList::new(now, DEFAULT_CRL_TTL_SECS);
        assert_eq!(crl.entries.len(), 0);
        assert!(!crl.is_revoked(&AgentId([0xAA; 32])));

        let encoded = crl.encode().unwrap();
        let decoded = RevocationList::decode(&encoded).unwrap();
        assert_eq!(decoded.entries.len(), 0);
    }

    #[test]
    fn test_revoked_ids() {
        let (_pk, sk, revoking_id) = make_keypair();
        let target1 = AgentId([0xAA; 32]);
        let target2 = AgentId([0xBB; 32]);
        let now = 1700000000u64;

        let mut crl = RevocationList::new(now, DEFAULT_CRL_TTL_SECS);
        crl.revoke(target1.clone(), now, None, revoking_id.clone(), &sk);
        crl.revoke(target2.clone(), now, None, revoking_id, &sk);

        let ids = crl.revoked_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&target1));
        assert!(ids.contains(&target2));
    }
}
