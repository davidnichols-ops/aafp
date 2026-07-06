//! DHT storage for third-party attestations (Phase E5, §10.3, §7.2).
//!
//! Attestations are stored under a separate key namespace from AgentRecords:
//!   key = SHA-256(b"aafp-attestation" || subject_agent_id || attester_agent_id)
//!
//! This keeps attested metrics (signed by third parties) decoupled from
//! self-signed AgentRecords, preventing agents from lying about their own
//! quality (§7.1).
//!
//! This is a stub module — function bodies are `todo!()` and will be
//! implemented in a subsequent build phase.

use crate::AgentId;
use std::collections::HashMap;

/// DHT key for an attestation: `SHA-256(b"aafp-attestation" || subject || attester)`.
pub type AttestationKey = [u8; 32];

/// In-memory attestation store with a separate key namespace from
/// `CapabilityDht`. Mirrors the in-memory approach of the capability DHT.
///
/// Attestations are indexed by `AttestationKey` (derived from
/// subject + attester AgentIds) with a reverse index by subject for
/// efficient prefix-style lookup of all attestations for a given agent.
#[derive(Debug, Default)]
pub struct AttestationStore {
    /// `AttestationKey -> attestation payload` (opaque bytes in stub form).
    store: HashMap<AttestationKey, Vec<u8>>,
    /// `SubjectAgentId -> Vec<AttestationKey>` (reverse index).
    by_subject: HashMap<AgentId, Vec<AttestationKey>>,
}

impl AttestationStore {
    /// Create a new empty attestation store.
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
            by_subject: HashMap::new(),
        }
    }

    /// Compute the DHT key for an attestation.
    ///
    /// `key = SHA-256(b"aafp-attestation" || subject.0 || attester.0)`
    ///
    /// # Stub
    /// This is a stub — SHA-256 hashing will be implemented in a subsequent phase.
    pub fn attestation_key(subject: &AgentId, attester: &AgentId) -> AttestationKey {
        let _ = (subject, attester);
        todo!("attestation_key: SHA-256(b\"aafp-attestation\" || subject || attester)")
    }

    /// Store an attestation.
    ///
    /// Verifies the signature and expiry first, then rejects self-attestations
    /// (where `attester == subject`) per §7.5 Sybil resistance.
    ///
    /// # Stub
    /// This is a stub — verification and storage will be implemented in a
    /// subsequent phase.
    pub fn store(
        &mut self,
        subject: &AgentId,
        attester: &AgentId,
        attestation_bytes: &[u8],
        expires_at: u64,
        now: u64,
    ) -> Result<(), AttestationStoreError> {
        let _ = (subject, attester, attestation_bytes, expires_at, now);
        todo!("store: verify signature/expiry, reject self-attestation, insert")
    }

    /// Get all attestations for a subject agent.
    ///
    /// # Stub
    /// This is a stub — lookup via the reverse index will be implemented in a
    /// subsequent phase.
    pub fn get_for_agent(&self, subject: &AgentId) -> Vec<&[u8]> {
        let _ = subject;
        todo!("get_for_agent: return all attestations for subject via by_subject index")
    }

    /// Reject self-attestations where `attester == subject` (§7.5).
    ///
    /// Returns `Err(SelfAttestation)` if the attester and subject are the
    /// same agent. This is called by [`store`](Self::store) before insertion.
    ///
    /// # Stub
    /// This is a stub — the check itself is trivial but is separated for
    /// testability; implementation will be added in a subsequent phase.
    pub fn reject_self_attestation(
        subject: &AgentId,
        attester: &AgentId,
    ) -> Result<(), AttestationStoreError> {
        let _ = (subject, attester);
        todo!("reject_self_attestation: Err if subject == attester")
    }

    /// Remove expired attestations.
    ///
    /// Returns the number of evicted entries.
    ///
    /// # Stub
    /// This is a stub — eviction logic will be implemented in a subsequent phase.
    pub fn evict_expired(&mut self, now: u64) -> usize {
        let _ = now;
        todo!("evict_expired: remove entries where expires_at <= now, return count")
    }

    /// Total number of attestations stored.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

/// Errors returned by `AttestationStore` operations.
#[derive(Debug, thiserror::Error)]
pub enum AttestationStoreError {
    /// Signature verification failed.
    #[error("attestation signature verification failed")]
    VerificationFailed,
    /// Self-attestation rejected (attester == subject, §7.5).
    #[error("self-attestation rejected (attester == subject)")]
    SelfAttestation,
    /// Attestation has expired.
    #[error("attestation expired at {0}")]
    Expired(u64),
}
