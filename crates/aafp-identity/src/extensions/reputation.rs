//! Reputation extension (Phase E4).
//!
//! Namespace: `"aafp.reputation.v1"`. **Self-reported reputation is NOT
//! trustworthy.** This extension carries only *references* to third-party
//! attestations. The actual attestation documents are stored separately in
//! the DHT (see `attestation.rs`).

use aafp_cbor::Value;
use crate::identity_v1::IdentityError;
use super::AgentRecordExtension;

/// Reputation extension: references to third-party attestations.
///
/// The actual trust score is computed by the *discovering* agent from
/// the referenced attestations, weighted by the discovering agent's trust
/// relationship with each attester (see `compute_reputation()` in
/// `attestation.rs`).
///
/// CBOR encoding:
/// ```cbor
/// ReputationExtensionData = {
///     ? 1: [ *tstr ],   // attestation_refs (SHA-256 hashes, hex)
///     ? 2: float,       // self_claimed_score (0-100, unverified)
///     ? 3: [ *tstr ],   // sources (DHT keys / URLs)
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReputationExtension {
    /// References to attestation records. Each entry is
    /// SHA-256(attestation_bytes), hex-encoded.
    pub attestation_refs: Vec<String>,
    /// Self-claimed trust score (0-100). Treated as unverified by
    /// consumers. Useful only as a hint, never for ranking.
    pub self_claimed_score: Option<f64>,
    /// URLs or DHT keys where attestations can be fetched.
    pub sources: Vec<String>,
}

impl AgentRecordExtension for ReputationExtension {
    const NAMESPACE: &'static str = "aafp.reputation.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        todo!()
    }

    fn from_cbor(_val: &Value) -> Result<Self, IdentityError> {
        todo!()
    }
}
