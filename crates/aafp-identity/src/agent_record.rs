//! AgentRecord: a self-signed record binding an agent's identity to its
//! capabilities and endpoints. Serialized as CBOR for wire format.

use crate::agent_id::{derive_agent_id, verify_agent_id};
use crate::keypair::{AgentKeypair, IdentityError};
use aafp_crypto::SignatureScheme;
use serde::{Deserialize, Serialize};

/// A self-signed agent record published to the DHT.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    /// SHA-256(public_key) — 32 bytes.
    pub agent_id: [u8; 32],
    /// ML-DSA-65 public key (1952 bytes).
    pub public_key: Vec<u8>,
    /// Capabilities this agent advertises (e.g., ["inference", "translation"]).
    pub capabilities: Vec<String>,
    /// How to reach this agent (e.g., ["quic://1.2.3.4:4433"]).
    pub endpoints: Vec<String>,
    /// Record version (monotonically increasing).
    pub version: u64,
    /// Unix epoch seconds when this record was created.
    pub timestamp: u64,
    /// Self-signed ML-DSA-65 signature over the CBOR-encoded record (excluding signature).
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for AgentRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRecord")
            .field(
                "agent_id",
                &crate::agent_id::agent_id_to_hex(&self.agent_id),
            )
            .field("capabilities", &self.capabilities)
            .field("endpoints", &self.endpoints)
            .field("version", &self.version)
            .field("timestamp", &self.timestamp)
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

impl AgentRecord {
    /// Create a new self-signed agent record.
    pub fn new(keypair: &AgentKeypair, capabilities: Vec<String>, endpoints: Vec<String>) -> Self {
        let agent_id = derive_agent_id(&keypair.public_key);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut record = Self {
            agent_id,
            public_key: keypair.public_key.clone(),
            capabilities,
            endpoints,
            version: 1,
            timestamp,
            signature: Vec::new(),
        };

        // Sign the record (excluding the signature field).
        let unsigned = record.unsigned_cbor();
        record.signature = keypair.sign(&unsigned);
        record
    }

    /// Create a new record with an explicit version and timestamp.
    pub fn new_with_version(
        keypair: &AgentKeypair,
        capabilities: Vec<String>,
        endpoints: Vec<String>,
        version: u64,
        timestamp: u64,
    ) -> Self {
        let agent_id = derive_agent_id(&keypair.public_key);
        let mut record = Self {
            agent_id,
            public_key: keypair.public_key.clone(),
            capabilities,
            endpoints,
            version,
            timestamp,
            signature: Vec::new(),
        };
        let unsigned = record.unsigned_cbor();
        record.signature = keypair.sign(&unsigned);
        record
    }

    /// Verify the self-signature and that the agent_id matches the public key.
    pub fn verify(&self) -> bool {
        // Check agent_id matches public_key.
        if !verify_agent_id(&self.agent_id, &self.public_key) {
            return false;
        }
        // Verify signature.
        let unsigned = self.unsigned_cbor();
        let pk = match aafp_crypto::MlDsa65PublicKey::from_bytes(&self.public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig = match aafp_crypto::MlDsa65Signature::from_bytes(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        aafp_crypto::MlDsa65::verify(&pk, &unsigned, &sig)
    }

    /// CBOR-encode the record (including signature) for wire transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    /// CBOR-decode a record from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, IdentityError> {
        ciborium::from_reader(data).map_err(|e| IdentityError::Deserialization(e.to_string()))
    }

    /// Encode the unsigned portion (all fields except signature) as CBOR.
    fn unsigned_cbor(&self) -> Vec<u8> {
        // We serialize a temporary struct without the signature field.
        #[derive(Serialize)]
        struct UnsignedRecord<'a> {
            agent_id: &'a [u8; 32],
            public_key: &'a [u8],
            capabilities: &'a [String],
            endpoints: &'a [String],
            version: u64,
            timestamp: u64,
        }

        let unsigned = UnsignedRecord {
            agent_id: &self.agent_id,
            public_key: &self.public_key,
            capabilities: &self.capabilities,
            endpoints: &self.endpoints,
            version: self.version,
            timestamp: self.timestamp,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&unsigned, &mut buf).expect("cbor serialization");
        buf
    }

    /// Convert to an RFC-0003 compliant v1 AgentRecord for wire serialization.
    ///
    /// The v1 record uses integer-keyed canonical CBOR and CapabilityDescriptor
    /// (structured capabilities with metadata). This conversion produces a
    /// record that can be serialized to RFC-compliant wire bytes via
    /// `AgentRecordV1::to_cbor()` / `aafp_cbor::encode()`.
    ///
    /// The signature is NOT recomputed — the existing signature is carried over.
    /// If the legacy record was signed with the legacy unsigned_cbor() format
    /// (string keys), the v1 signature will NOT verify against the v1 CBOR
    /// encoding. Call `sign()` on the v1 record to re-sign with the correct
    /// v1 signature input.
    pub fn to_v1(&self) -> crate::identity_v1::AgentRecord {
        use crate::identity_v1::{
            AgentRecord as V1Record, CapabilityDescriptor, KEY_ALG_ML_DSA_65,
        };

        let caps: Vec<CapabilityDescriptor> = self
            .capabilities
            .iter()
            .map(CapabilityDescriptor::new)
            .collect();

        let mut record = V1Record::new(
            &self.public_key,
            caps,
            self.endpoints.clone(),
            self.timestamp,
            self.timestamp + 86400, // 24-hour expiry default
            KEY_ALG_ML_DSA_65,
        );
        // Carry over the existing signature (may need re-signing for v1 format)
        record.signature = self.signature.clone();
        record
    }

    /// Convert to an RFC-0003 compliant v1 AgentRecord and re-sign it
    /// with the v1 signature format (domain-separated, integer-keyed CBOR).
    ///
    /// This produces a fully valid v1 record with a correct signature.
    pub fn to_v1_signed(
        &self,
        keypair: &AgentKeypair,
    ) -> Result<crate::identity_v1::AgentRecord, IdentityError> {
        use crate::identity_v1::{
            AgentRecord as V1Record, CapabilityDescriptor, KEY_ALG_ML_DSA_65,
        };

        let caps: Vec<CapabilityDescriptor> = self
            .capabilities
            .iter()
            .map(CapabilityDescriptor::new)
            .collect();

        let mut record = V1Record::new(
            &self.public_key,
            caps,
            self.endpoints.clone(),
            self.timestamp,
            self.timestamp + 86400,
            KEY_ALG_ML_DSA_65,
        );

        // Sign with v1 format: "aafp-v1-record" || canonical_CBOR(fields 1-7,9)
        let sk = keypair.secret_key()?;
        record.sign(&sk);
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify() {
        let kp = AgentKeypair::generate();
        let record = AgentRecord::new(
            &kp,
            vec!["inference".into(), "translation".into()],
            vec!["quic://127.0.0.1:4433".into()],
        );
        assert!(record.verify());
    }

    #[test]
    fn cbor_roundtrip() {
        let kp = AgentKeypair::generate();
        let record = AgentRecord::new(
            &kp,
            vec!["inference".into()],
            vec!["quic://1.2.3.4:4433".into()],
        );
        let bytes = record.to_bytes().unwrap();
        let decoded = AgentRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.agent_id, record.agent_id);
        assert_eq!(decoded.public_key, record.public_key);
        assert_eq!(decoded.capabilities, record.capabilities);
        assert_eq!(decoded.endpoints, record.endpoints);
        assert_eq!(decoded.version, record.version);
        assert_eq!(decoded.signature, record.signature);
        assert!(decoded.verify());
    }

    #[test]
    fn tampered_record_fails_verification() {
        let kp = AgentKeypair::generate();
        let mut record = AgentRecord::new(&kp, vec!["inference".into()], vec![]);
        assert!(record.verify());
        // Tamper with capabilities.
        record.capabilities.push("forged".into());
        assert!(!record.verify());
    }

    #[test]
    fn wrong_agent_id_fails() {
        let kp = AgentKeypair::generate();
        let mut record = AgentRecord::new(&kp, vec!["inference".into()], vec![]);
        // Tamper with agent_id.
        record.agent_id[0] ^= 0xff;
        assert!(!record.verify());
    }

    #[test]
    fn version_and_timestamp() {
        let kp = AgentKeypair::generate();
        let record = AgentRecord::new_with_version(&kp, vec!["cap".into()], vec![], 42, 1234567890);
        assert_eq!(record.version, 42);
        assert_eq!(record.timestamp, 1234567890);
        assert!(record.verify());
    }
}
