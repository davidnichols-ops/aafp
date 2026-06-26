//! AAFP identity layer: ML-DSA-65 keypairs, 32-byte AgentIDs, self-signed
//! AgentRecords, and UCAN capability delegation chains.
//!
//! See `AAFP_Architecture_Deliverable.md` Phase 2.3 for the identity design.

pub mod agent_id;
pub mod agent_record;
pub mod keypair;
pub mod ucan;

pub use agent_id::{
    agent_id_from_hex, agent_id_short, agent_id_to_hex, derive_agent_id, verify_agent_id, AgentId,
};
pub use agent_record::AgentRecord;
pub use keypair::{AgentKeypair, IdentityError};
pub use ucan::{Capability, UcanHeader, UcanPayload, UcanToken};
