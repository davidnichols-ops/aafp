//! AAFP v1 Identity and Authentication (RFC-0003).
//!
//! Implements:
//! - AgentId derivation (SHA-256 of public key)
//! - AgentId fingerprint (base32 + CRC32)
//! - AgentRecord (self-signed CBOR document with integer keys)
//! - CapabilityDescriptor
//! - Domain separators for signatures

use aafp_cbor::{int_map, str_map, Value};
use aafp_crypto::{
    MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme,
    ML_DSA_65_PUBKEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use sha2::{Digest, Sha256};

/// Domain separator for AgentRecord signatures (RFC-0003 §3.5).
pub const RECORD_DOMAIN_SEPARATOR: &[u8] = b"aafp-v1-record";

/// Domain separator for UCAN token signatures (RFC-0003 §3.5).
pub const UCAN_DOMAIN_SEPARATOR: &[u8] = b"aafp-v1-ucan";

/// Record type string for v1 AgentRecords (RFC-0003 §3.3).
pub const RECORD_TYPE_V1: &str = "aafp-record-v1";

/// Key algorithm: ML-DSA-65 = 1 (RFC-0003 §2.3).
pub const KEY_ALG_ML_DSA_65: u64 = 1;

/// AgentId size: 32 bytes (SHA-256 output).
pub const AGENT_ID_SIZE: usize = 32;

/// Maximum AgentRecord expiry: 30 days in seconds (RFC-0003 §8.4).
pub const MAX_RECORD_EXPIRY: u64 = 30 * 24 * 60 * 60; // 2,592,000

/// Recommended AgentRecord renewal interval: 7 days (RFC-0003 §8.4).
pub const RECOMMENDED_RENEWAL: u64 = 7 * 24 * 60 * 60; // 604,800

/// An AgentId: 32-byte SHA-256 hash of an agent's public key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AgentId(pub [u8; AGENT_ID_SIZE]);

impl AgentId {
    /// Derive AgentId from a public key: SHA-256(public_key).
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let hash = Sha256::digest(public_key);
        let mut arr = [0u8; AGENT_ID_SIZE];
        arr.copy_from_slice(&hash);
        Self(arr)
    }

    /// Create from raw 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != AGENT_ID_SIZE {
            return Err(IdentityError::InvalidAgentIdLength {
                expected: AGENT_ID_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; AGENT_ID_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; AGENT_ID_SIZE] {
        &self.0
    }

    /// Hex encoding (64-character lowercase).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short form for display: first 16 hex chars with 0x prefix.
    pub fn to_short_hex(&self) -> String {
        format!("0x{}", &hex::encode(&self.0[..8]))
    }

    /// Human-readable fingerprint (RFC-0003 §2.6):
    /// `AAFP-<base32(first_16_bytes)>-<CRC32_hex>`
    pub fn to_fingerprint(&self) -> String {
        let first_16 = &self.0[..16];
        let base32 = base32_encode(first_16);
        let crc = crc32(first_16);
        format!("AAFP-{}-{:08X}", base32, crc)
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_short_hex())
    }
}

/// AgentRecord (RFC-0003 §3).
///
/// CBOR structure (integer keys):
/// ```cbor
/// AgentRecord = {
///     1: tstr,          // record_type: "aafp-record-v1"
///     2: bstr,          // agent_id: 32 bytes
///     3: bstr,          // public_key
///     4: [ *CapabilityDescriptor ],  // capabilities
///     5: [ *tstr ],     // endpoints (multiaddr strings)
///     6: uint,          // created_at
///     7: uint,          // expires_at
///     8: bstr,          // signature
///     9: uint,          // key_algorithm
/// }
/// ```
#[derive(Clone, Debug)]
pub struct AgentRecord {
    pub record_type: String,
    pub agent_id: AgentId,
    pub public_key: Vec<u8>,
    pub capabilities: Vec<CapabilityDescriptor>,
    pub endpoints: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub signature: Vec<u8>,
    pub key_algorithm: u64,
}

impl AgentRecord {
    /// Create a new AgentRecord with the given key and parameters.
    /// The signature is NOT computed — call `sign()` to compute it.
    pub fn new(
        public_key: &[u8],
        capabilities: Vec<CapabilityDescriptor>,
        endpoints: Vec<String>,
        created_at: u64,
        expires_at: u64,
        key_algorithm: u64,
    ) -> Self {
        let agent_id = AgentId::from_public_key(public_key);
        Self {
            record_type: RECORD_TYPE_V1.to_string(),
            agent_id,
            public_key: public_key.to_vec(),
            capabilities,
            endpoints,
            created_at,
            expires_at,
            signature: Vec::new(),
            key_algorithm,
        }
    }

    /// Encode to canonical CBOR, excluding the signature (key 8).
    /// This is the signature input per RFC-0003 §3.4.
    pub fn to_cbor_without_sig(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.record_type.clone())),
            (2, Value::ByteString(self.agent_id.0.to_vec())),
            (3, Value::ByteString(self.public_key.clone())),
            (
                4,
                Value::Array(
                    self.capabilities
                        .iter()
                        .map(|c| c.to_cbor())
                        .collect(),
                ),
            ),
            (
                5,
                Value::Array(
                    self.endpoints
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ),
            (6, Value::Unsigned(self.created_at)),
            (7, Value::Unsigned(self.expires_at)),
            (9, Value::Unsigned(self.key_algorithm)),
        ])
    }

    /// Encode to canonical CBOR with all fields (including signature).
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.record_type.clone())),
            (2, Value::ByteString(self.agent_id.0.to_vec())),
            (3, Value::ByteString(self.public_key.clone())),
            (
                4,
                Value::Array(
                    self.capabilities
                        .iter()
                        .map(|c| c.to_cbor())
                        .collect(),
                ),
            ),
            (
                5,
                Value::Array(
                    self.endpoints
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ),
            (6, Value::Unsigned(self.created_at)),
            (7, Value::Unsigned(self.expires_at)),
            (8, Value::ByteString(self.signature.clone())),
            (9, Value::Unsigned(self.key_algorithm)),
        ])
    }

    /// Decode from a CBOR Value.
    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        let record_type = match get(1) {
            Some(Value::TextString(s)) => s.clone(),
            Some(other) => {
                return Err(IdentityError::InvalidField {
                    field: "record_type",
                    message: format!("expected tstr, got {:?}", other),
                })
            }
            None => return Err(IdentityError::MissingField("record_type")),
        };

        let agent_id_bytes = match get(2) {
            Some(Value::ByteString(b)) => b.clone(),
            Some(other) => {
                return Err(IdentityError::InvalidField {
                    field: "agent_id",
                    message: format!("expected bstr, got {:?}", other),
                })
            }
            None => return Err(IdentityError::MissingField("agent_id")),
        };
        let agent_id = AgentId::from_bytes(&agent_id_bytes)?;

        let public_key = match get(3) {
            Some(Value::ByteString(b)) => b.clone(),
            Some(other) => {
                return Err(IdentityError::InvalidField {
                    field: "public_key",
                    message: format!("expected bstr, got {:?}", other),
                })
            }
            None => return Err(IdentityError::MissingField("public_key")),
        };

        let capabilities = match get(4) {
            Some(Value::Array(arr)) => {
                let mut caps = Vec::new();
                for item in arr {
                    caps.push(CapabilityDescriptor::from_cbor(item)?);
                }
                caps
            }
            Some(other) => {
                return Err(IdentityError::InvalidField {
                    field: "capabilities",
                    message: format!("expected array, got {:?}", other),
                })
            }
            None => return Err(IdentityError::MissingField("capabilities")),
        };

        let endpoints = match get(5) {
            Some(Value::Array(arr)) => {
                let mut eps = Vec::new();
                for item in arr {
                    match item {
                        Value::TextString(s) => eps.push(s.clone()),
                        other => {
                            return Err(IdentityError::InvalidField {
                                field: "endpoints",
                                message: format!("expected tstr in array, got {:?}", other),
                            })
                        }
                    }
                }
                eps
            }
            Some(other) => {
                return Err(IdentityError::InvalidField {
                    field: "endpoints",
                    message: format!("expected array, got {:?}", other),
                })
            }
            None => return Err(IdentityError::MissingField("endpoints")),
        };

        let created_at = expect_u64(get(6), "created_at")?;
        let expires_at = expect_u64(get(7), "expires_at")?;
        let signature = expect_bstr(get(8), "signature")?;
        let key_algorithm = expect_u64(get(9), "key_algorithm")?;

        Ok(Self {
            record_type,
            agent_id,
            public_key,
            capabilities,
            endpoints,
            created_at,
            expires_at,
            signature,
            key_algorithm,
        })
    }

    /// Sign the record with the given secret key (RFC-0003 §3.4).
    pub fn sign(&mut self, secret_key: &MlDsa65SecretKey) {
        let cbor = self.to_cbor_without_sig();
        let cbor_bytes = aafp_cbor::encode(&cbor).unwrap();
        let mut sig_input = Vec::with_capacity(RECORD_DOMAIN_SEPARATOR.len() + cbor_bytes.len());
        sig_input.extend_from_slice(RECORD_DOMAIN_SEPARATOR);
        sig_input.extend_from_slice(&cbor_bytes);
        let sig = MlDsa65::sign(secret_key, &sig_input);
        self.signature = sig.0;
    }

    /// Verify the record's signature and fields (RFC-0003 §3.6).
    pub fn verify(&self, now: u64) -> Result<(), IdentityError> {
        // Step 2: Verify agent_id == SHA-256(public_key)
        let computed_id = AgentId::from_public_key(&self.public_key);
        if self.agent_id != computed_id {
            return Err(IdentityError::InvalidAgentId);
        }

        // Step 7: Check record_type
        if self.record_type != RECORD_TYPE_V1 {
            return Err(IdentityError::InvalidRecordType {
                got: self.record_type.clone(),
            });
        }

        // Step 8: Check key_algorithm
        if self.key_algorithm != KEY_ALG_ML_DSA_65 {
            return Err(IdentityError::UnsupportedAlgorithm {
                code: self.key_algorithm,
            });
        }

        // Step 3-5: Verify signature
        let cbor = self.to_cbor_without_sig();
        let cbor_bytes = aafp_cbor::encode(&cbor).unwrap();
        let mut sig_input = Vec::with_capacity(RECORD_DOMAIN_SEPARATOR.len() + cbor_bytes.len());
        sig_input.extend_from_slice(RECORD_DOMAIN_SEPARATOR);
        sig_input.extend_from_slice(&cbor_bytes);

        let pk = MlDsa65PublicKey::from_bytes(&self.public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let sig = MlDsa65Signature::from_bytes(&self.signature)
            .map_err(|_| IdentityError::InvalidSignatureLength)?;
        if !MlDsa65::verify(&pk, &sig_input, &sig) {
            return Err(IdentityError::SignatureVerificationFailed);
        }

        // Step 6: Check expiry
        if self.expires_at <= now {
            return Err(IdentityError::Expired {
                expires_at: self.expires_at,
                now,
            });
        }

        Ok(())
    }

    /// Check if the record is expired at the given time.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at <= now
    }

    /// Check if the record's expiry exceeds the 30-day maximum (RFC-0003 §8.4).
    pub fn exceeds_max_expiry(&self) -> bool {
        (self.expires_at - self.created_at) > MAX_RECORD_EXPIRY
    }
}

/// CapabilityDescriptor (RFC-0003 §4).
///
/// CBOR structure (integer keys):
/// ```cbor
/// CapabilityDescriptor = {
///     1: tstr,                    // name
///     2: { *tstr => MetadataValue },  // metadata (string keys!)
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityDescriptor {
    pub name: String,
    pub metadata: Vec<(String, MetadataValue)>,
}

impl CapabilityDescriptor {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            metadata: Vec::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: MetadataValue) -> Self {
        self.metadata.push((key.into(), value));
        self
    }

    /// Encode to canonical CBOR.
    /// Note: metadata map uses STRING keys (RFC-0002 §8.1 exception).
    pub fn to_cbor(&self) -> Value {
        let metadata_val = if self.metadata.is_empty() {
            Value::StrMap(vec![])
        } else {
            str_map(
                self.metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_cbor()))
                    .collect(),
            )
        };
        int_map(vec![
            (1, Value::TextString(self.name.clone())),
            (2, metadata_val),
        ])
    }

    /// Decode from a CBOR Value.
    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        let name = match get(1) {
            Some(Value::TextString(s)) => s.clone(),
            Some(other) => {
                return Err(IdentityError::InvalidField {
                    field: "name",
                    message: format!("expected tstr, got {:?}", other),
                })
            }
            None => return Err(IdentityError::MissingField("name")),
        };

        let metadata = match get(2) {
            Some(Value::StrMap(entries)) => {
                let mut md = Vec::new();
                for (k, v) in entries {
                    md.push((k.clone(), MetadataValue::from_cbor(v)?));
                }
                md
            }
            Some(Value::IntMap(_)) => Vec::new(), // Empty map decoded as IntMap
            None => Vec::new(),                   // Metadata is optional
            Some(other) => {
                return Err(IdentityError::InvalidField {
                    field: "metadata",
                    message: format!("expected map, got {:?}", other),
                })
            }
        };

        Ok(Self { name, metadata })
    }
}

/// MetadataValue (RFC-0003 §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetadataValue {
    Bool(bool),
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
}

impl MetadataValue {
    pub fn to_cbor(&self) -> Value {
        match self {
            Self::Bool(b) => Value::Bool(*b),
            Self::Int(n) => {
                if *n >= 0 {
                    Value::Unsigned(*n as u64)
                } else {
                    Value::Negative(*n)
                }
            }
            Self::Text(s) => Value::TextString(s.clone()),
            Self::Bytes(b) => Value::ByteString(b.clone()),
        }
    }

    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        match val {
            Value::Bool(b) => Ok(Self::Bool(*b)),
            Value::Unsigned(n) => Ok(Self::Int(*n as i64)),
            Value::Negative(n) => Ok(Self::Int(*n)),
            Value::TextString(s) => Ok(Self::Text(s.clone())),
            Value::ByteString(b) => Ok(Self::Bytes(b.clone())),
            other => Err(IdentityError::InvalidField {
                field: "metadata_value",
                message: format!("unsupported value type: {:?}", other),
            }),
        }
    }
}

/// Identity errors.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid AgentId length: expected {expected}, got {actual}")]
    InvalidAgentIdLength { expected: usize, actual: usize },
    #[error("AgentId does not match SHA-256(public_key)")]
    InvalidAgentId,
    #[error("invalid record_type: expected \"{RECORD_TYPE_V1}\", got \"{got}\"")]
    InvalidRecordType { got: String },
    #[error("unsupported key algorithm: {code}")]
    UnsupportedAlgorithm { code: u64 },
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("identity expired: expires_at={expires_at}, now={now}")]
    Expired { expires_at: u64, now: u64 },
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid field '{field}': {message}")]
    InvalidField {
        field: &'static str,
        message: String,
    },
    #[error("CBOR error: {0}")]
    Cbor(#[from] aafp_cbor::CborError),
}

// Helper functions

fn expect_u64(val: Option<&Value>, field: &'static str) -> Result<u64, IdentityError> {
    match val {
        Some(Value::Unsigned(n)) => Ok(*n),
        Some(other) => Err(IdentityError::InvalidField {
            field,
            message: format!("expected uint, got {:?}", other),
        }),
        None => Err(IdentityError::MissingField(field)),
    }
}

fn expect_bstr(val: Option<&Value>, field: &'static str) -> Result<Vec<u8>, IdentityError> {
    match val {
        Some(Value::ByteString(b)) => Ok(b.clone()),
        Some(other) => Err(IdentityError::InvalidField {
            field,
            message: format!("expected bstr, got {:?}", other),
        }),
        None => Err(IdentityError::MissingField(field)),
    }
}

/// RFC 4648 base32 encoding (no padding, uppercase).
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u32 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }
    result
}

/// CRC-32 (IEEE 802.3 polynomial) checksum.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_id_derivation() {
        let (pk, _sk) = MlDsa65::keypair();
        let agent_id = AgentId::from_public_key(&pk.0);
        assert_eq!(agent_id.0.len(), AGENT_ID_SIZE);

        // Same key → same AgentId
        let agent_id2 = AgentId::from_public_key(&pk.0);
        assert_eq!(agent_id, agent_id2);

        // Different key → different AgentId
        let (pk2, _) = MlDsa65::keypair();
        let agent_id3 = AgentId::from_public_key(&pk2.0);
        assert_ne!(agent_id, agent_id3);
    }

    #[test]
    fn test_agent_id_hex() {
        let agent_id = AgentId([0xa1u8; 32]);
        assert_eq!(agent_id.to_hex(), "a1".repeat(32));
        assert_eq!(agent_id.to_short_hex(), "0xa1a1a1a1a1a1a1a1");
    }

    #[test]
    fn test_agent_id_fingerprint() {
        let agent_id = AgentId([0u8; 32]);
        let fp = agent_id.to_fingerprint();
        assert!(fp.starts_with("AAFP-"));
        // First 16 zero bytes → base32 "AAAAAAAAAAAAAAAA"
        // CRC32 of 16 zero bytes = 0x6522DF69
        assert!(fp.contains("-"));
    }

    #[test]
    fn test_agent_id_from_bytes() {
        let bytes = [0x42u8; 32];
        let agent_id = AgentId::from_bytes(&bytes).unwrap();
        assert_eq!(agent_id.0, bytes);

        // Wrong length
        assert!(AgentId::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_agent_record_create_sign_verify() {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;
        let expires = now + 7 * 24 * 60 * 60; // 7 days

        let mut record = AgentRecord::new(
            &pk.0,
            vec![CapabilityDescriptor::new("inference")],
            vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
            now,
            expires,
            KEY_ALG_ML_DSA_65,
        );

        // Sign
        record.sign(&sk);

        // Verify
        assert!(record.verify(now).is_ok());
    }

    #[test]
    fn test_agent_record_cbor_roundtrip() {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;

        let mut record = AgentRecord::new(
            &pk.0,
            vec![
                CapabilityDescriptor::new("inference")
                    .with_metadata("model", MetadataValue::Text("gpt-4".to_string()))
                    .with_metadata("max_tokens", MetadataValue::Int(8192)),
            ],
            vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
            now,
            now + 86400,
            KEY_ALG_ML_DSA_65,
        );
        record.sign(&sk);

        // Encode to CBOR
        let cbor = record.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();

        // Decode from CBOR
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let record2 = AgentRecord::from_cbor(&decoded).unwrap();

        assert_eq!(record2.record_type, record.record_type);
        assert_eq!(record2.agent_id, record.agent_id);
        assert_eq!(record2.public_key, record.public_key);
        assert_eq!(record2.endpoints, record.endpoints);
        assert_eq!(record2.created_at, record.created_at);
        assert_eq!(record2.expires_at, record.expires_at);
        assert_eq!(record2.signature, record.signature);
        assert_eq!(record2.key_algorithm, record.key_algorithm);
        assert_eq!(record2.capabilities.len(), 1);
        assert_eq!(record2.capabilities[0].name, "inference");

        // Verify the decoded record
        assert!(record2.verify(now).is_ok());
    }

    #[test]
    fn test_agent_record_verify_rejects_bad_agent_id() {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;

        let mut record = AgentRecord::new(
            &pk.0,
            vec![],
            vec![],
            now,
            now + 86400,
            KEY_ALG_ML_DSA_65,
        );
        record.sign(&sk);

        // Tamper with agent_id
        record.agent_id = AgentId([0xFFu8; 32]);

        let err = record.verify(now).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidAgentId));
    }

    #[test]
    fn test_agent_record_verify_rejects_expired() {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;

        let mut record = AgentRecord::new(
            &pk.0,
            vec![],
            vec![],
            now,
            now + 100, // Expires in 100 seconds
            KEY_ALG_ML_DSA_65,
        );
        record.sign(&sk);

        // Verify at now + 200 (after expiry)
        let err = record.verify(now + 200).unwrap_err();
        assert!(matches!(err, IdentityError::Expired { .. }));
    }

    #[test]
    fn test_agent_record_verify_rejects_bad_signature() {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;

        let mut record = AgentRecord::new(
            &pk.0,
            vec![],
            vec![],
            now,
            now + 86400,
            KEY_ALG_ML_DSA_65,
        );
        record.sign(&sk);

        // Tamper with signature
        record.signature[0] ^= 0xFF;

        let err = record.verify(now).unwrap_err();
        assert!(matches!(err, IdentityError::SignatureVerificationFailed));
    }

    #[test]
    fn test_agent_record_verify_rejects_wrong_record_type() {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;

        let mut record = AgentRecord::new(
            &pk.0,
            vec![],
            vec![],
            now,
            now + 86400,
            KEY_ALG_ML_DSA_65,
        );
        record.sign(&sk);

        // Tamper with record_type
        record.record_type = "wrong-type".to_string();

        let err = record.verify(now).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidRecordType { .. }));
    }

    #[test]
    fn test_capability_descriptor_roundtrip() {
        let cap = CapabilityDescriptor::new("inference")
            .with_metadata("model", MetadataValue::Text("gpt-4".to_string()))
            .with_metadata("max_tokens", MetadataValue::Int(8192))
            .with_metadata("enabled", MetadataValue::Bool(true));

        let cbor = cap.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let cap2 = CapabilityDescriptor::from_cbor(&decoded).unwrap();

        assert_eq!(cap2.name, cap.name);
        assert_eq!(cap2.metadata.len(), cap.metadata.len());
    }

    #[test]
    fn test_capability_descriptor_empty_metadata() {
        let cap = CapabilityDescriptor::new("translation");
        let cbor = cap.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let cap2 = CapabilityDescriptor::from_cbor(&decoded).unwrap();
        assert_eq!(cap2.name, "translation");
        assert!(cap2.metadata.is_empty());
    }

    #[test]
    fn test_max_expiry_check() {
        let (pk, _) = MlDsa65::keypair();
        let now = 1700000000u64;

        // 7-day record: OK
        let record = AgentRecord::new(&pk.0, vec![], vec![], now, now + 7 * 86400, 1);
        assert!(!record.exceeds_max_expiry());

        // 31-day record: exceeds max
        let record = AgentRecord::new(&pk.0, vec![], vec![], now, now + 31 * 86400, 1);
        assert!(record.exceeds_max_expiry());
    }

    #[test]
    fn test_base32_encoding() {
        // Test known vectors
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(&[0x66]), "MY");
        assert_eq!(base32_encode(&[0x66, 0x6f]), "MZXQ");
        assert_eq!(base32_encode(&[0x66, 0x6f, 0x6f]), "MZXW6");
    }

    #[test]
    fn test_crc32() {
        // CRC32 of empty string = 0x00000000
        assert_eq!(crc32(&[]), 0);
        // CRC32 of "123456789" = 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }
}
