//! Third-party attestation system (Phase E3).
//!
//! Attestations are separate signed documents, stored in the DHT under a
//! different key namespace. They are **NOT** part of the AgentRecord
//! signature — they are signed by the attester, not the subject.

use crate::agent_id::agent_id_to_hex;
use crate::identity_v1::{AgentId, IdentityError};
use crate::keypair::{AgentKeypair, IdentityError as KeypairError};
use crate::trust_manager::{TrustManager, TrustResult};
use crate::ucan::{Capability, UcanToken};
use crate::web_of_trust::{TRUST_LEVEL_FULL, TRUST_LEVEL_MARGINAL, TRUST_LEVEL_ULTIMATE};
use aafp_cbor::{encode, int_map, int_map_get, Value};
use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme};
use sha2::{Digest, Sha256};

/// Convert a keypair-layer IdentityError into an identity_v1 IdentityError.
fn map_keypair_err(e: KeypairError) -> IdentityError {
    match e {
        KeypairError::SignatureVerificationFailed => IdentityError::SignatureVerificationFailed,
        KeypairError::AgentIdMismatch => IdentityError::InvalidAgentId,
        KeypairError::Crypto(c) => IdentityError::InvalidField {
            field: "crypto",
            message: c.to_string(),
        },
        other => IdentityError::InvalidField {
            field: "ucan",
            message: other.to_string(),
        },
    }
}

/// Domain separator for attestation signatures.
pub const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"aafp-v1-attestation";

/// Record type string for attestations.
pub const ATTESTATION_TYPE_V1: &str = "aafp-attestation-v1";

/// A third-party attestation about an agent's performance/reputation.
#[derive(Clone, Debug)]
pub struct Attestation {
    pub record_type: String,
    pub subject_agent_id: AgentId,
    pub attester_agent_id: AgentId,
    pub attester_public_key: Vec<u8>,
    pub attested_at: u64,
    pub expires_at: u64,
    pub data: AttestationData,
    pub signature: Vec<u8>,
}

/// The metrics being attested by a third party.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationData {
    pub observed_avg_latency_ms: Option<u16>,
    pub observed_success_rate_bps: Option<u16>,
    pub sample_count: u32,
    pub trust_score: u8,
    pub notes: Option<String>,
}

impl AttestationData {
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = Vec::new();
        if let Some(lat) = self.observed_avg_latency_ms {
            entries.push((1, Value::Unsigned(lat as u64)));
        }
        if let Some(bps) = self.observed_success_rate_bps {
            entries.push((2, Value::Unsigned(bps as u64)));
        }
        entries.push((3, Value::Unsigned(self.sample_count as u64)));
        entries.push((4, Value::Unsigned(self.trust_score as u64)));
        if let Some(notes) = &self.notes {
            entries.push((5, Value::TextString(notes.clone())));
        }
        int_map(entries)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        Ok(Self {
            observed_avg_latency_ms: match int_map_get(val, 1) {
                Some(Value::Unsigned(n)) if *n <= u16::MAX as u64 => Some(*n as u16),
                _ => None,
            },
            observed_success_rate_bps: match int_map_get(val, 2) {
                Some(Value::Unsigned(n)) if *n <= u16::MAX as u64 => Some(*n as u16),
                _ => None,
            },
            sample_count: match int_map_get(val, 3) {
                Some(Value::Unsigned(n)) if *n <= u32::MAX as u64 => *n as u32,
                _ => 0,
            },
            trust_score: match int_map_get(val, 4) {
                Some(Value::Unsigned(n)) if *n <= u8::MAX as u64 => *n as u8,
                _ => 0,
            },
            notes: match int_map_get(val, 5) {
                Some(Value::TextString(s)) => Some(s.clone()),
                _ => None,
            },
        })
    }
}

impl Attestation {
    pub fn to_cbor_without_sig(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.record_type.clone())),
            (2, Value::ByteString(self.subject_agent_id.0.to_vec())),
            (3, Value::ByteString(self.attester_agent_id.0.to_vec())),
            (4, Value::ByteString(self.attester_public_key.clone())),
            (5, Value::Unsigned(self.attested_at)),
            (6, Value::Unsigned(self.expires_at)),
            (7, self.data.to_cbor()),
        ])
    }

    pub fn to_cbor(&self) -> Value {
        let mut entries = match self.to_cbor_without_sig() {
            Value::IntMap(e) => e,
            _ => unreachable!(),
        };
        entries.push((8, Value::ByteString(self.signature.clone())));
        Value::IntMap(entries)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let record_type = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(IdentityError::MissingField("record_type")),
        };
        if record_type != ATTESTATION_TYPE_V1 {
            return Err(IdentityError::InvalidRecordType { got: record_type });
        }
        let subject = match int_map_get(val, 2) {
            Some(Value::ByteString(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                AgentId(arr)
            }
            _ => return Err(IdentityError::MissingField("subject_agent_id")),
        };
        let attester = match int_map_get(val, 3) {
            Some(Value::ByteString(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                AgentId(arr)
            }
            _ => return Err(IdentityError::MissingField("attester_agent_id")),
        };
        let attester_pk = match int_map_get(val, 4) {
            Some(Value::ByteString(b)) if b.len() == aafp_crypto::ML_DSA_65_PUBKEY_LEN => b.clone(),
            _ => return Err(IdentityError::MissingField("attester_public_key")),
        };
        let attested_at = match int_map_get(val, 5) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(IdentityError::MissingField("attested_at")),
        };
        let expires_at = match int_map_get(val, 6) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(IdentityError::MissingField("expires_at")),
        };
        let data = match int_map_get(val, 7) {
            Some(v) => AttestationData::from_cbor(v)?,
            None => return Err(IdentityError::MissingField("data")),
        };
        let signature = match int_map_get(val, 8) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => Vec::new(),
        };
        Ok(Self {
            record_type,
            subject_agent_id: subject,
            attester_agent_id: attester,
            attester_public_key: attester_pk,
            attested_at,
            expires_at,
            data,
            signature,
        })
    }

    pub fn dht_key(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"aafp-attestation");
        h.update(self.subject_agent_id.0);
        h.update(self.attester_agent_id.0);
        let result = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    pub fn create_and_sign(
        attester: &AgentKeypair,
        subject_agent_id: AgentId,
        expires_at: u64,
        data: AttestationData,
        now: u64,
    ) -> Result<Self, IdentityError> {
        let attester_id = AgentId::from_public_key(&attester.public_key);
        let mut att = Self {
            record_type: ATTESTATION_TYPE_V1.to_string(),
            subject_agent_id,
            attester_agent_id: attester_id,
            attester_public_key: attester.public_key.clone(),
            attested_at: now,
            expires_at,
            data,
            signature: Vec::new(),
        };
        let sk = MlDsa65SecretKey::from_bytes(&attester.secret_key).map_err(|e| {
            IdentityError::InvalidField {
                field: "attester_secret_key",
                message: e.to_string(),
            }
        })?;
        att.sign(&sk)?;
        Ok(att)
    }

    pub fn sign(&mut self, secret_key: &MlDsa65SecretKey) -> Result<(), IdentityError> {
        let cbor = self.to_cbor_without_sig();
        let bytes = encode(&cbor).map_err(|e| IdentityError::InvalidField {
            field: "attestation",
            message: e.to_string(),
        })?;
        let mut input = Vec::new();
        input.extend_from_slice(ATTESTATION_DOMAIN_SEPARATOR);
        input.extend_from_slice(&bytes);
        self.signature = MlDsa65::sign(secret_key, &input).0;
        Ok(())
    }

    pub fn verify(&self, now: u64) -> Result<(), IdentityError> {
        let computed = AgentId::from_public_key(&self.attester_public_key);
        if self.attester_agent_id != computed {
            return Err(IdentityError::InvalidAgentId);
        }
        if self.record_type != ATTESTATION_TYPE_V1 {
            return Err(IdentityError::InvalidRecordType {
                got: self.record_type.clone(),
            });
        }
        let cbor = self.to_cbor_without_sig();
        let bytes = encode(&cbor).map_err(|e| IdentityError::InvalidField {
            field: "attestation",
            message: e.to_string(),
        })?;
        let mut input = Vec::new();
        input.extend_from_slice(ATTESTATION_DOMAIN_SEPARATOR);
        input.extend_from_slice(&bytes);
        let pk = MlDsa65PublicKey::from_bytes(&self.attester_public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let sig = MlDsa65Signature::from_bytes(&self.signature)
            .map_err(|_| IdentityError::InvalidSignatureLength)?;
        if !MlDsa65::verify(&pk, &input, &sig) {
            return Err(IdentityError::SignatureVerificationFailed);
        }
        if self.expires_at <= now {
            return Err(IdentityError::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }
}

/// Errors that can occur during attestation operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationError {
    InvalidSignature,
    InvalidAgentId,
    Expired,
    SelfAttestation,
}

/// Compute a weighted reputation score from multiple attestations.
pub fn compute_reputation(
    attestations: &[Attestation],
    trust_manager: &TrustManager,
    now: u64,
) -> Option<f64> {
    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;

    for att in attestations {
        if att.verify(now).is_err() {
            continue;
        }
        if att.attester_agent_id == att.subject_agent_id {
            continue;
        }
        let trust =
            trust_manager.verify_peer(&att.attester_agent_id, &att.attester_public_key, None, now);
        let weight = match trust {
            TrustResult::Trusted { level, .. } => match level {
                TRUST_LEVEL_ULTIMATE => 1.0,
                TRUST_LEVEL_FULL => 1.0,
                TRUST_LEVEL_MARGINAL => 0.5,
                _ => 0.0,
            },
            TrustResult::Unknown { .. } => 0.1,
            _ => 0.0,
        };
        if weight == 0.0 {
            continue;
        }
        let sample_factor = if att.data.sample_count < 10 {
            0.3
        } else if att.data.sample_count < 100 {
            0.7
        } else {
            1.0
        };
        let final_weight = weight * sample_factor;
        weighted_sum += final_weight * att.data.trust_score as f64;
        total_weight += final_weight;
    }

    if total_weight > 0.0 {
        Some(weighted_sum / total_weight)
    } else {
        None
    }
}

/// Verify that an attestation is backed by a valid UCAN delegation chain.
pub fn verify_attestation_authorization(
    attestation: &Attestation,
    ucan_chain: &[&UcanToken],
    root_public_key: &[u8],
) -> Result<(), IdentityError> {
    UcanToken::verify_chain(ucan_chain, root_public_key).map_err(map_keypair_err)?;

    let leaf = ucan_chain.last().ok_or(IdentityError::InvalidField {
        field: "ucan_chain",
        message: "empty chain".into(),
    })?;
    let has_attest_cap = leaf
        .payload
        .cap
        .iter()
        .any(|c| c.resource == "attest.reputation" && c.action == "invoke");
    if !has_attest_cap {
        return Err(IdentityError::InvalidField {
            field: "ucan_chain",
            message: "no attest.reputation capability in chain".into(),
        });
    }

    let attester_id_hex = agent_id_to_hex(&attestation.attester_agent_id.0);
    if leaf.payload.aud != attester_id_hex {
        return Err(IdentityError::InvalidField {
            field: "ucan_chain",
            message: format!(
                "UCAN audience {} does not match attester {}",
                leaf.payload.aud, attester_id_hex
            ),
        });
    }

    Ok(())
}

/// Create a UCAN token delegating the `attest.reputation` capability.
pub fn delegate_attest_capability(
    issuer: &AgentKeypair,
    audience: &AgentId,
    expires_at: u64,
) -> Result<UcanToken, IdentityError> {
    UcanToken::delegate(
        issuer,
        &audience.0,
        vec![Capability {
            resource: "attest.reputation".into(),
            action: "invoke".into(),
            constraints: None,
        }],
        expires_at,
    )
    .map_err(map_keypair_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_cbor::{decode, encode};

    #[test]
    fn test_attestation_cbor_roundtrip() {
        let att = Attestation {
            record_type: ATTESTATION_TYPE_V1.into(),
            subject_agent_id: AgentId([1u8; 32]),
            attester_agent_id: AgentId([2u8; 32]),
            attester_public_key: vec![0xAA; 1952],
            attested_at: 1700000000,
            expires_at: 1700086400,
            data: AttestationData {
                observed_avg_latency_ms: Some(15),
                observed_success_rate_bps: Some(9995),
                sample_count: 100,
                trust_score: 82,
                notes: Some("Reliable".into()),
            },
            signature: vec![0xBB; 4627],
        };
        let cbor = att.to_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let att2 = Attestation::from_cbor(&decoded).unwrap();
        assert_eq!(att2.record_type, att.record_type);
        assert_eq!(att2.subject_agent_id, att.subject_agent_id);
        assert_eq!(att2.attester_agent_id, att.attester_agent_id);
        assert_eq!(att2.data, att.data);
        assert_eq!(att2.signature, att.signature);
    }

    #[test]
    fn test_attestation_sign_verify() {
        let (attester_kp, subject_kp) = (AgentKeypair::generate(), AgentKeypair::generate());
        let now = 1700000000u64;
        let subject_id = AgentId::from_public_key(&subject_kp.public_key);

        let att = Attestation::create_and_sign(
            &attester_kp,
            subject_id,
            now + 86400,
            AttestationData {
                observed_avg_latency_ms: Some(20),
                sample_count: 50,
                trust_score: 75,
                ..Default::default()
            },
            now,
        )
        .unwrap();

        assert!(att.verify(now).is_ok());
        assert!(att.verify(now + 86400 + 1).is_err()); // expired
    }

    #[test]
    fn test_dht_key_deterministic() {
        let att = Attestation {
            record_type: ATTESTATION_TYPE_V1.into(),
            subject_agent_id: AgentId([1u8; 32]),
            attester_agent_id: AgentId([2u8; 32]),
            attester_public_key: vec![0xAA; 1952],
            attested_at: 1700000000,
            expires_at: 1700086400,
            data: AttestationData::default(),
            signature: vec![],
        };
        let key1 = att.dht_key();
        let key2 = att.dht_key();
        assert_eq!(key1, key2);
    }
}
