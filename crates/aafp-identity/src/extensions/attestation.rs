//! Third-party attestation system (Phase E3).
//!
//! Attestations are separate signed documents, stored in the DHT under a
//! different key namespace. They are **NOT** part of the AgentRecord
//! signature — they are signed by the attester, not the subject.

use crate::agent_id::AgentId;

/// Domain separator for attestation signatures.
pub const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"aafp-v1-attestation";

/// A third-party attestation about an agent's performance/reputation.
///
/// CBOR structure (integer keys):
/// ```cbor
/// Attestation = {
///     1: tstr,      // record_type: "aafp-attestation-v1"
///     2: bstr,      // subject_agent_id (32 bytes)
///     3: bstr,      // attester_agent_id (32 bytes)
///     4: bstr,      // attester_signature
///     5: tstr,      // metric
///     6: float,     // value
///     7: uint,      // timestamp (unix seconds)
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Attestation {
    /// The agent issuing the attestation.
    pub attester_id: AgentId,
    /// ML-DSA-65 signature over (domain_sep || cbor_without_sig).
    pub signature: Vec<u8>,
    /// The metric being attested (e.g., "latency_ms", "success_rate").
    pub metric: String,
    /// The attested value for the metric.
    pub value: f64,
    /// When the attestation was created (unix seconds).
    pub timestamp: u64,
}

impl Attestation {
    /// Verify the attestation's signature and validity.
    ///
    /// Checks:
    /// 1. Signature is valid over (domain_sep || cbor_without_sig)
    /// 2. Not expired (if an expiry is applicable)
    /// 3. record_type is correct
    pub fn verify(&self, _now: u64) -> Result<(), AttestationError> {
        todo!()
    }
}

/// Errors that can occur during attestation verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationError {
    /// The signature did not verify against the attester's public key.
    InvalidSignature,
    /// The attester AgentId does not match the derived public key.
    InvalidAttesterId,
    /// The attestation has expired.
    Expired,
    /// The record type was not the expected attestation type.
    InvalidRecordType,
    /// The attested metric is unknown or malformed.
    InvalidMetric,
    /// The attested value is out of the valid range for the metric.
    InvalidValue,
    /// CBOR decoding failed.
    DecodeError(String),
}
