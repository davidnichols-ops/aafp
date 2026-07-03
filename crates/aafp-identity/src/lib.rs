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
pub mod identity_v1;
pub mod keypair;
/// CRL-based identity revocation (RFC-0003 amendment).
pub mod revocation;
pub mod ucan;

pub use agent_id::{
    agent_id_from_hex, agent_id_short, agent_id_to_hex, derive_agent_id, verify_agent_id, AgentId,
};
// v1 RFC-compliant types (integer keys, canonical CBOR per RFC-0003).
// Use these for wire serialization.
pub use identity_v1::{
    AgentRecord as AgentRecordV1, CapabilityDescriptor, IdentityError as IdentityErrorV1,
    MetadataValue, KEY_ALG_ML_DSA_65, MAX_RECORD_EXPIRY, RECOMMENDED_RENEWAL,
    RECORD_DOMAIN_SEPARATOR, RECORD_TYPE_V1, UCAN_DOMAIN_SEPARATOR,
};
pub use keypair::{AgentKeypair, IdentityError};
pub use revocation::{
    RevocationEntry, RevocationError, RevocationList, RevocationStore, DEFAULT_CRL_TTL_SECS,
};
pub use ucan::{Capability, UcanHeader, UcanPayload, UcanToken};
