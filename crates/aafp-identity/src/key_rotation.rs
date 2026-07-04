//! Key Rotation: old key signs new key, preserving trust across key changes
//! (RFC 0011 §6).
//!
//! When an agent needs to generate a new keypair (e.g., key compromise
//! concern, algorithm upgrade), it creates a KeyRotationRecord signed by
//! both the old and new keys. This proves continuity of identity.
//!
//! CBOR structure (RFC 0011 §6.2):
//! ```cbor
//! KeyRotationRecord = {
//!     1: tstr,    // type: "aafp-rotation-v1"
//!     2: bstr,    // old_agent_id: 32 bytes
//!     3: bstr,    // new_agent_id: 32 bytes
//!     4: bstr,    // new_public_key: 1952 bytes
//!     5: uint,    // timestamp: unix timestamp
//!     6: bstr,    // old_signature: ML-DSA-65 over fields 1-5
//!                 //   with domain separator "aafp-v1-rotation"
//!     7: bstr,    // new_signature: ML-DSA-65 over fields 1-5
//!                 //   with domain separator "aafp-v1-rotation"
//! }
//! ```

use crate::identity_v1::{AgentId, IdentityError};
use crate::revocation::{RevocationEntry, RevocationList};
use aafp_cbor::{decode, encode, int_map, int_map_get, CborError, Value};
use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme};
use thiserror::Error;

/// Domain separator for key rotation signatures (RFC 0011 §6.3).
pub const ROTATION_DOMAIN_SEPARATOR: &[u8] = b"aafp-v1-rotation";

/// Type string for key rotation records (RFC 0011 §6.2).
pub const ROTATION_TYPE_V1: &str = "aafp-rotation-v1";

/// Key rotation errors.
#[derive(Debug, Error)]
pub enum RotationError {
    /// CBOR encoding/decoding error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    /// Old signature verification failed.
    #[error("old signature verification failed")]
    OldSignatureFailed,
    /// New signature verification failed.
    #[error("new signature verification failed")]
    NewSignatureFailed,
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
    /// Old agent_id does not match old public key.
    #[error("old agent_id does not match old public key")]
    OldAgentIdMismatch,
    /// New agent_id does not match new public key.
    #[error("new agent_id does not match new public key")]
    NewAgentIdMismatch,
    /// Invalid public key.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Invalid signature length.
    #[error("invalid signature length")]
    InvalidSignatureLength,
    /// Only one signature present (both old and new required).
    #[error("both signatures required")]
    MissingSignature,
    /// Identity error (e.g., invalid AgentId).
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

/// A key rotation record: proves that the holder of `old_key` has rotated
/// to `new_key` (RFC 0011 §6.2).
///
/// Both the old and new keys must sign the same data. This proves:
/// - The old key authorized the rotation (old_signature)
/// - The new key is controlled by the same entity (new_signature)
#[derive(Clone, Debug)]
pub struct KeyRotationRecord {
    /// Type string, always `"aafp-rotation-v1"`.
    pub record_type: String,
    /// 32-byte AgentId of the old key.
    pub old_agent_id: AgentId,
    /// 32-byte AgentId of the new key.
    pub new_agent_id: AgentId,
    /// New ML-DSA-65 public key (1952 bytes).
    pub new_public_key: Vec<u8>,
    /// Timestamp of the rotation (unix seconds).
    pub timestamp: u64,
    /// ML-DSA-65 signature by the old key over fields 1-5.
    pub old_signature: Vec<u8>,
    /// ML-DSA-65 signature by the new key over fields 1-5.
    pub new_signature: Vec<u8>,
}

impl KeyRotationRecord {
    /// Create a key rotation record signed by both old and new keys
    /// (RFC 0011 §6.5).
    ///
    /// The `old_public_key` is needed to verify the old_agent_id matches,
    /// but is NOT included in the record (the old key is expected to be
    /// known from the directory, WoT, or prior connection).
    pub fn new(
        old_agent_id: AgentId,
        new_agent_id: AgentId,
        new_public_key: &[u8],
        timestamp: u64,
        old_secret_key: &MlDsa65SecretKey,
        new_secret_key: &MlDsa65SecretKey,
    ) -> Self {
        let mut record = Self {
            record_type: ROTATION_TYPE_V1.to_string(),
            old_agent_id,
            new_agent_id,
            new_public_key: new_public_key.to_vec(),
            timestamp,
            old_signature: Vec::new(),
            new_signature: Vec::new(),
        };
        let sig_input = record.signature_input();
        record.old_signature = MlDsa65::sign(old_secret_key, &sig_input).0;
        record.new_signature = MlDsa65::sign(new_secret_key, &sig_input).0;
        record
    }

    /// Compute the signature input (fields 1-5 with domain separator).
    fn signature_input(&self) -> Vec<u8> {
        let cbor = self.to_cbor_without_sig();
        let cbor_bytes = encode(&cbor).unwrap_or_default();
        let mut input = Vec::with_capacity(ROTATION_DOMAIN_SEPARATOR.len() + cbor_bytes.len());
        input.extend_from_slice(ROTATION_DOMAIN_SEPARATOR);
        input.extend_from_slice(&cbor_bytes);
        input
    }

    /// Encode to CBOR without the signature fields (for signing).
    fn to_cbor_without_sig(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.record_type.clone())),
            (2, Value::ByteString(self.old_agent_id.0.to_vec())),
            (3, Value::ByteString(self.new_agent_id.0.to_vec())),
            (4, Value::ByteString(self.new_public_key.clone())),
            (5, Value::Unsigned(self.timestamp)),
        ])
    }

    /// Encode to CBOR (with both signatures).
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.record_type.clone())),
            (2, Value::ByteString(self.old_agent_id.0.to_vec())),
            (3, Value::ByteString(self.new_agent_id.0.to_vec())),
            (4, Value::ByteString(self.new_public_key.clone())),
            (5, Value::Unsigned(self.timestamp)),
            (6, Value::ByteString(self.old_signature.clone())),
            (7, Value::ByteString(self.new_signature.clone())),
        ])
    }

    /// Decode from a CBOR Value.
    pub fn from_cbor(val: &Value) -> Result<Self, RotationError> {
        let get = |k: i64| -> Option<&Value> { int_map_get(val, k) };

        let record_type = match get(1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(RotationError::MissingField("type")),
        };

        let old_agent_id = match get(2) {
            Some(Value::ByteString(b)) => AgentId::from_bytes(b)?,
            _ => return Err(RotationError::MissingField("old_agent_id")),
        };

        let new_agent_id = match get(3) {
            Some(Value::ByteString(b)) => AgentId::from_bytes(b)?,
            _ => return Err(RotationError::MissingField("new_agent_id")),
        };

        let new_public_key = match get(4) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => return Err(RotationError::MissingField("new_public_key")),
        };

        let timestamp = match get(5) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RotationError::MissingField("timestamp")),
        };

        let old_signature = match get(6) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => return Err(RotationError::MissingField("old_signature")),
        };

        let new_signature = match get(7) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => return Err(RotationError::MissingField("new_signature")),
        };

        Ok(Self {
            record_type,
            old_agent_id,
            new_agent_id,
            new_public_key,
            timestamp,
            old_signature,
            new_signature,
        })
    }

    /// Encode to CBOR bytes.
    pub fn encode_bytes(&self) -> Result<Vec<u8>, RotationError> {
        Ok(encode(&self.to_cbor())?)
    }

    /// Decode from CBOR bytes.
    pub fn decode_bytes(data: &[u8]) -> Result<Self, RotationError> {
        let (val, _) = decode(data)?;
        Self::from_cbor(&val)
    }

    /// Verify the rotation record (RFC 0011 §6.4).
    ///
    /// Checks:
    /// 1. type == "aafp-rotation-v1"
    /// 2. new_agent_id == SHA-256(new_public_key)
    /// 3. old_agent_id == SHA-256(old_public_key) (caller provides old_public_key)
    /// 4. old_signature verifies using old_public_key
    /// 5. new_signature verifies using new_public_key
    /// 6. Both signatures MUST verify.
    pub fn verify(&self, old_public_key: &MlDsa65PublicKey, now: u64) -> Result<(), RotationError> {
        // Step 1: Check type
        if self.record_type != ROTATION_TYPE_V1 {
            return Err(RotationError::InvalidField {
                field: "type",
                message: format!("expected {}, got {}", ROTATION_TYPE_V1, self.record_type),
            });
        }

        // Step 2: Check new_agent_id == SHA-256(new_public_key)
        let computed_new_id = AgentId::from_public_key(&self.new_public_key);
        if self.new_agent_id != computed_new_id {
            return Err(RotationError::NewAgentIdMismatch);
        }

        // Step 3: Check old_agent_id == SHA-256(old_public_key)
        let computed_old_id = AgentId::from_public_key(old_public_key.as_ref());
        if self.old_agent_id != computed_old_id {
            return Err(RotationError::OldAgentIdMismatch);
        }

        // Step 4-5: Verify both signatures
        let sig_input = self.signature_input();

        let old_sig = MlDsa65Signature::from_bytes(&self.old_signature)
            .map_err(|_| RotationError::InvalidSignatureLength)?;
        if !MlDsa65::verify(old_public_key, &sig_input, &old_sig) {
            return Err(RotationError::OldSignatureFailed);
        }

        let new_pk = MlDsa65PublicKey::from_bytes(&self.new_public_key)
            .map_err(|_| RotationError::InvalidPublicKey)?;
        let new_sig = MlDsa65Signature::from_bytes(&self.new_signature)
            .map_err(|_| RotationError::InvalidSignatureLength)?;
        if !MlDsa65::verify(&new_pk, &sig_input, &new_sig) {
            return Err(RotationError::NewSignatureFailed);
        }

        let _ = now; // Timestamp is informational; callers may check freshness
        Ok(())
    }

    /// Create a revocation entry for the old key (RFC 0011 §6.5 step 6).
    ///
    /// After rotation, the old key should be revoked.
    pub fn revoke_old_key(
        &self,
        old_secret_key: &MlDsa65SecretKey,
        reason: Option<String>,
    ) -> RevocationEntry {
        RevocationEntry::new(
            self.old_agent_id,
            self.timestamp,
            reason,
            self.old_agent_id,
            old_secret_key,
        )
    }

    /// Create a CRL containing the old key revocation.
    pub fn create_revocation_crl(
        &self,
        old_secret_key: &MlDsa65SecretKey,
        ttl_secs: u64,
        reason: Option<String>,
    ) -> RevocationList {
        let mut crl = RevocationList::new(self.timestamp, ttl_secs);
        crl.revoke(
            self.old_agent_id,
            self.timestamp,
            reason,
            self.old_agent_id,
            old_secret_key,
        );
        crl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::AgentKeypair;

    fn make_keypair() -> AgentKeypair {
        AgentKeypair::generate()
    }

    #[test]
    fn test_rotation_sign_and_verify() {
        let old_kp = make_keypair();
        let new_kp = make_keypair();
        let old_id = AgentId::from_public_key(&old_kp.public_key);
        let new_id = AgentId::from_public_key(&new_kp.public_key);
        let now = 1_000_000u64;

        let record = KeyRotationRecord::new(
            old_id,
            new_id,
            &new_kp.public_key,
            now,
            &old_kp.secret_key().unwrap(),
            &new_kp.secret_key().unwrap(),
        );

        let old_pk = old_kp.public_key().unwrap();
        assert!(record.verify(&old_pk, now).is_ok());
    }

    #[test]
    fn test_rotation_wrong_old_key() {
        let old_kp = make_keypair();
        let new_kp = make_keypair();
        let wrong_kp = make_keypair();
        let old_id = AgentId::from_public_key(&old_kp.public_key);
        let new_id = AgentId::from_public_key(&new_kp.public_key);
        let now = 1_000_000u64;

        let record = KeyRotationRecord::new(
            old_id,
            new_id,
            &new_kp.public_key,
            now,
            &old_kp.secret_key().unwrap(),
            &new_kp.secret_key().unwrap(),
        );

        // Verify with wrong old public key
        let wrong_pk = wrong_kp.public_key().unwrap();
        assert!(matches!(
            record.verify(&wrong_pk, now),
            Err(RotationError::OldAgentIdMismatch)
        ));
    }

    #[test]
    fn test_rotation_old_signature_failed() {
        let old_kp = make_keypair();
        let new_kp = make_keypair();
        let impostor_kp = make_keypair();
        let old_id = AgentId::from_public_key(&old_kp.public_key);
        let new_id = AgentId::from_public_key(&new_kp.public_key);
        let now = 1_000_000u64;

        // Sign old_signature with impostor key (not the real old key)
        let mut record = KeyRotationRecord::new(
            old_id,
            new_id,
            &new_kp.public_key,
            now,
            &old_kp.secret_key().unwrap(),
            &new_kp.secret_key().unwrap(),
        );
        // Tamper: re-sign old_signature with impostor
        let sig_input = record.signature_input();
        record.old_signature = MlDsa65::sign(&impostor_kp.secret_key().unwrap(), &sig_input).0;

        let old_pk = old_kp.public_key().unwrap();
        assert!(matches!(
            record.verify(&old_pk, now),
            Err(RotationError::OldSignatureFailed)
        ));
    }

    #[test]
    fn test_rotation_new_signature_failed() {
        let old_kp = make_keypair();
        let new_kp = make_keypair();
        let impostor_kp = make_keypair();
        let old_id = AgentId::from_public_key(&old_kp.public_key);
        let new_id = AgentId::from_public_key(&new_kp.public_key);
        let now = 1_000_000u64;

        let mut record = KeyRotationRecord::new(
            old_id,
            new_id,
            &new_kp.public_key,
            now,
            &old_kp.secret_key().unwrap(),
            &new_kp.secret_key().unwrap(),
        );
        // Tamper: re-sign new_signature with impostor
        let sig_input = record.signature_input();
        record.new_signature = MlDsa65::sign(&impostor_kp.secret_key().unwrap(), &sig_input).0;

        let old_pk = old_kp.public_key().unwrap();
        assert!(matches!(
            record.verify(&old_pk, now),
            Err(RotationError::NewSignatureFailed)
        ));
    }

    #[test]
    fn test_rotation_new_agent_id_mismatch() {
        let old_kp = make_keypair();
        let new_kp = make_keypair();
        let old_id = AgentId::from_public_key(&old_kp.public_key);
        let wrong_new_id = AgentId([0xFF; 32]);
        let now = 1_000_000u64;

        let record = KeyRotationRecord::new(
            old_id,
            wrong_new_id,
            &new_kp.public_key,
            now,
            &old_kp.secret_key().unwrap(),
            &new_kp.secret_key().unwrap(),
        );

        let old_pk = old_kp.public_key().unwrap();
        assert!(matches!(
            record.verify(&old_pk, now),
            Err(RotationError::NewAgentIdMismatch)
        ));
    }

    #[test]
    fn test_cbor_roundtrip() {
        let old_kp = make_keypair();
        let new_kp = make_keypair();
        let old_id = AgentId::from_public_key(&old_kp.public_key);
        let new_id = AgentId::from_public_key(&new_kp.public_key);
        let now = 1_000_000u64;

        let record = KeyRotationRecord::new(
            old_id,
            new_id,
            &new_kp.public_key,
            now,
            &old_kp.secret_key().unwrap(),
            &new_kp.secret_key().unwrap(),
        );

        let encoded = record.encode_bytes().unwrap();
        let decoded = KeyRotationRecord::decode_bytes(&encoded).unwrap();
        assert_eq!(decoded.record_type, record.record_type);
        assert_eq!(decoded.old_agent_id, record.old_agent_id);
        assert_eq!(decoded.new_agent_id, record.new_agent_id);
        assert_eq!(decoded.new_public_key, record.new_public_key);
        assert_eq!(decoded.timestamp, record.timestamp);
        assert_eq!(decoded.old_signature, record.old_signature);
        assert_eq!(decoded.new_signature, record.new_signature);
    }

    #[test]
    fn test_revoke_old_key() {
        let old_kp = make_keypair();
        let new_kp = make_keypair();
        let old_id = AgentId::from_public_key(&old_kp.public_key);
        let new_id = AgentId::from_public_key(&new_kp.public_key);
        let now = 1_000_000u64;

        let record = KeyRotationRecord::new(
            old_id,
            new_id,
            &new_kp.public_key,
            now,
            &old_kp.secret_key().unwrap(),
            &new_kp.secret_key().unwrap(),
        );

        let entry = record.revoke_old_key(&old_kp.secret_key().unwrap(), Some("rotated".into()));
        assert_eq!(entry.agent_id, old_id);
        let old_pk = old_kp.public_key().unwrap();
        assert!(entry.verify(&old_pk));
    }

    #[test]
    fn test_create_revocation_crl() {
        let old_kp = make_keypair();
        let new_kp = make_keypair();
        let old_id = AgentId::from_public_key(&old_kp.public_key);
        let new_id = AgentId::from_public_key(&new_kp.public_key);
        let now = 1_000_000u64;

        let record = KeyRotationRecord::new(
            old_id,
            new_id,
            &new_kp.public_key,
            now,
            &old_kp.secret_key().unwrap(),
            &new_kp.secret_key().unwrap(),
        );

        let crl = record.create_revocation_crl(&old_kp.secret_key().unwrap(), 3600, None);
        assert!(crl.is_revoked(&old_id));
        assert!(!crl.is_revoked(&new_id));
    }
}
