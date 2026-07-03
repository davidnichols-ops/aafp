#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::all)]
#![allow(missing_docs)]

//! AAFP Protocol Conformance Test Suite
//!
//! This crate provides conformance tests that map directly to normative
//! requirements in the AAFP RFCs (Revision 3). Each test is tagged with
//! its source RFC section and requirement ID from COMPLIANCE_MATRIX.md.
//!
//! Conformance test helpers and imports are intentionally permissive: many
//! helpers exist for future test expansion and imports are kept broad so
//! individual test modules can pull what they need without churn.
//!
//! ## Test Organization
//!
//! - `rfc0002`: Transport and framing (RFC-0002)
//! - `rfc0003`: Identity and authentication (RFC-0003)
//! - `rfc0004`: Discovery (RFC-0004)
//! - `rfc0005`: Error model (RFC-0005)
//! - `rfc0006`: Capability negotiation (RFC-0006)
//!
//! Each test module documents which normative requirements it covers.

pub mod adversarial;
pub mod close_adversarial;
pub mod close_conformance;
pub mod close_differential;
pub mod close_property;
pub mod close_resources;
pub mod handshake_state_machine;
pub mod handshake_vectors;
pub mod mldsa_cross_matrix;
pub mod mldsa_cross_verify;
pub mod mldsa_differential;
pub mod mldsa_negative;
pub mod mldsa_property;
pub mod mldsa_rfc_verify;
pub mod negative;
pub mod pipeline_adversarial;
pub mod pipeline_order;
pub mod protocol_compliance;
pub mod replay_conformance;
pub mod replay_differential;
pub mod replay_stress;
pub mod rfc0002;
pub mod rfc0003;
pub mod rfc0004;
pub mod rfc0005;
pub mod test_vectors;
pub mod version_negotiation;
