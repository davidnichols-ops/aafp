//! AAFP identity layer: ML-DSA-65 keypairs, 32-byte AgentIDs, self-signed
//! AgentRecords, and UCAN capability delegation chains.
//!
//! See `AAFP_Architecture_Deliverable.md` Phase 2.3 for the identity design.

pub mod agent_id;
pub mod agent_record;
pub mod identity_v1;
pub mod keypair;
pub mod ucan;

pub use agent_id::{
    agent_id_from_hex, agent_id_short, agent_id_to_hex, derive_agent_id, verify_agent_id, AgentId,
};
pub use agent_record::AgentRecord;
pub use identity_v1::{
    AgentId as AgentIdV1, AgentRecord as AgentRecordV1, CapabilityDescriptor,
    CapabilityDescriptor as CapabilityDescriptorV1, IdentityError as IdentityErrorV1,
    MetadataValue, RECORD_DOMAIN_SEPARATOR, RECORD_TYPE_V1, UCAN_DOMAIN_SEPARATOR,
    KEY_ALG_ML_DSA_65, MAX_RECORD_EXPIRY, RECOMMENDED_RENEWAL,
};
pub use keypair::{AgentKeypair, IdentityError};
pub use ucan::{Capability, UcanHeader, UcanPayload, UcanToken};
