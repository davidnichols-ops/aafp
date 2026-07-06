//! DHT storage for third-party attestations (Phase E5, §10.3, §7.2).
//!
//! Attestations are stored under a separate key namespace from AgentRecords:
//!   key = SHA-256(b"aafp-attestation" || subject_agent_id || attester_agent_id)

use super::attestation::Attestation;
use crate::identity_v1::AgentId;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// DHT key for an attestation.
pub type AttestationKey = [u8; 32];

/// In-memory attestation store with a separate key namespace.
#[derive(Debug, Default)]
pub struct AttestationStore {
    store: HashMap<AttestationKey, Attestation>,
    by_subject: HashMap<AgentId, Vec<AttestationKey>>,
}

impl AttestationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attestation_key(subject: &AgentId, attester: &AgentId) -> AttestationKey {
        let mut hasher = Sha256::new();
        hasher.update(b"aafp-attestation");
        hasher.update(subject.0);
        hasher.update(attester.0);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    pub fn store(
        &mut self,
        subject: &AgentId,
        attester: &AgentId,
        attestation: Attestation,
        now: u64,
    ) -> Result<(), AttestationStoreError> {
        attestation
            .verify(now)
            .map_err(|_| AttestationStoreError::VerificationFailed)?;

        if subject == attester {
            return Err(AttestationStoreError::SelfAttestation);
        }

        let key = Self::attestation_key(subject, attester);
        self.by_subject.entry(*subject).or_default().push(key);
        self.store.insert(key, attestation);
        Ok(())
    }

    pub fn get_for_agent(&self, subject: &AgentId) -> Vec<&Attestation> {
        self.by_subject
            .get(subject)
            .map(|keys| keys.iter().filter_map(|k| self.store.get(k)).collect())
            .unwrap_or_default()
    }

    pub fn get(&self, subject: &AgentId, attester: &AgentId) -> Option<&Attestation> {
        let key = Self::attestation_key(subject, attester);
        self.store.get(&key)
    }

    pub fn evict_expired(&mut self, now: u64) -> usize {
        let expired_keys: Vec<AttestationKey> = self
            .store
            .iter()
            .filter(|(_, att)| att.expires_at <= now)
            .map(|(k, _)| *k)
            .collect();
        let count = expired_keys.len();
        for key in &expired_keys {
            if let Some(att) = self.store.remove(key) {
                if let Some(keys) = self.by_subject.get_mut(&att.subject_agent_id) {
                    keys.retain(|k| k != key);
                }
            }
        }
        count
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

/// Errors returned by `AttestationStore` operations.
#[derive(Debug, thiserror::Error)]
pub enum AttestationStoreError {
    #[error("attestation signature verification failed")]
    VerificationFailed,
    #[error("self-attestation rejected (attester == subject)")]
    SelfAttestation,
}

#[cfg(test)]
mod tests {
    use super::super::attestation::{AttestationData, ATTESTATION_TYPE_V1};
    use super::*;
    use crate::keypair::AgentKeypair;

    #[test]
    fn test_attestation_key_deterministic() {
        let subject = AgentId([1u8; 32]);
        let attester = AgentId([2u8; 32]);
        let k1 = AttestationStore::attestation_key(&subject, &attester);
        let k2 = AttestationStore::attestation_key(&subject, &attester);
        assert_eq!(k1, k2);

        let k3 = AttestationStore::attestation_key(&attester, &subject);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_store_and_retrieve() {
        let attester_kp = AgentKeypair::generate();
        let subject_kp = AgentKeypair::generate();
        let subject_id = AgentId::from_public_key(&subject_kp.public_key);
        let now = 1700000000u64;

        let att = Attestation::create_and_sign(
            &attester_kp,
            subject_id,
            now + 86400,
            AttestationData {
                sample_count: 50,
                trust_score: 80,
                ..Default::default()
            },
            now,
        )
        .unwrap();

        let mut store = AttestationStore::new();
        let attester_id = AgentId::from_public_key(&attester_kp.public_key);
        store.store(&subject_id, &attester_id, att, now).unwrap();

        let retrieved = store.get_for_agent(&subject_id);
        assert_eq!(retrieved.len(), 1);
    }

    #[test]
    fn test_reject_self_attestation() {
        let kp = AgentKeypair::generate();
        let agent_id = AgentId::from_public_key(&kp.public_key);
        let now = 1700000000u64;

        let att = Attestation::create_and_sign(
            &kp,
            agent_id,
            now + 86400,
            AttestationData::default(),
            now,
        )
        .unwrap();

        let mut store = AttestationStore::new();
        let result = store.store(&agent_id, &agent_id, att, now);
        assert!(result.is_err());
    }
}
