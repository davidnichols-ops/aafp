//! AAFP identity layer: ML-DSA-65 keypairs, 32-byte AgentIDs, self-signed
//! AgentRecords, and UCAN capability delegation chains.
//!
//! See `AAFP_Architecture_Deliverable.md` Phase 2.3 for the identity design.

pub mod agent_id;
/// Legacy MVP AgentRecord module. Uses serde with string keys — NOT RFC-compliant.
/// Use [`identity_v1`] instead for wire serialization.
#[deprecated = "Use identity_v1 instead. Legacy agent_record uses serde/string keys, not RFC-compliant."]
#[allow(deprecated)]
pub mod agent_record;
/// CA certificates for enterprise deployments (RFC 0011 §5).
pub mod ca_certificate;
/// AgentRecord extensions (geo, performance, cost, semantic, reputation, etc.)
pub mod extensions;
pub mod identity_v1;
/// Key rotation: old key signs new key (RFC 0011 §6).
pub mod key_directory;
pub mod key_rotation;
pub mod keypair;
/// CRL-based identity revocation (RFC-0003 amendment).
pub mod revocation;
/// Networked revocation distribution (RFC 0011 §7).
pub mod revocation_distribution;
/// TrustManager: unified trust verification API (RFC 0011 §8).
pub mod trust_manager;
pub mod ucan;
/// Web of Trust: peer-to-peer key signing (RFC 0011 §4).
pub mod web_of_trust;

pub use agent_id::{
    agent_id_from_hex, agent_id_short, agent_id_to_hex, derive_agent_id, verify_agent_id, AgentId,
};
// v1 RFC-compliant types (integer keys, canonical CBOR per RFC-0003).
// Use these for wire serialization.
pub use ca_certificate::{
    CaCertificate, CaError, CaVerifier, CA_CERT_TYPE_V1, CA_DOMAIN_SEPARATOR,
};
pub use identity_v1::{
    AgentRecord as AgentRecordV1, CapabilityDescriptor, IdentityError as IdentityErrorV1,
    MetadataValue, KEY_ALG_ML_DSA_65, MAX_RECORD_EXPIRY, RECOMMENDED_RENEWAL,
    RECORD_DOMAIN_SEPARATOR, RECORD_TYPE_V1, UCAN_DOMAIN_SEPARATOR,
};
pub use key_rotation::{
    KeyRotationRecord, RotationError, ROTATION_DOMAIN_SEPARATOR, ROTATION_TYPE_V1,
};
pub use keypair::{AgentKeypair, IdentityError};
pub use revocation::{
    RevocationEntry, RevocationError, RevocationList, RevocationStore, DEFAULT_CRL_TTL_SECS,
};
pub use revocation_distribution::{
    RevocationDistError, RevocationGossip, RevocationRpcHandler,
    DEFAULT_GOSSIP_INTERVAL_SECS as DEFAULT_REVOCATION_GOSSIP_INTERVAL_SECS,
    METHOD_REVOCATION_LIST, METHOD_REVOCATION_PUBLISH, METHOD_REVOCATION_QUERY,
};
pub use trust_manager::{TrustManager, TrustPolicy, TrustResult, TrustSource, TrustSuggestion};
pub use ucan::{Capability, UcanHeader, UcanPayload, UcanToken};
pub use web_of_trust::{
    TrustSignature, WebOfTrust, WotError, RECOMMENDED_WOT_VALIDITY_SECS, TRUST_LEVEL_FULL,
    TRUST_LEVEL_MARGINAL, TRUST_LEVEL_NONE, TRUST_LEVEL_ULTIMATE, WOT_DOMAIN_SEPARATOR,
    WOT_SIG_TYPE_V1,
};

// Extension re-exports
pub use extensions::{
    compute_reputation, delegate_attest_capability, verify_attestation_authorization,
    AgentRecordExtension, Attestation, AttestationData, AttestationError, AttestationKey,
    AttestationStore, AttestationStoreError, CapabilityVersionExtension, CostExtension,
    GeoExtension, HeartbeatExtension, HeartbeatTracker, HeartbeatUpdate, PerformanceExtension,
    ReputationExtension, SemanticExtension, SemanticVersion, ATTESTATION_DOMAIN_SEPARATOR,
    ATTESTATION_TYPE_V1,
};
