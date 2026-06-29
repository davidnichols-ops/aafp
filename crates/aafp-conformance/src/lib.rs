//! AAFP Protocol Conformance Test Suite
//!
//! This crate provides conformance tests that map directly to normative
//! requirements in the AAFP RFCs (Revision 3). Each test is tagged with
//! its source RFC section and requirement ID from COMPLIANCE_MATRIX.md.
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

pub mod rfc0002;
pub mod rfc0003;
pub mod rfc0004;
pub mod rfc0005;
pub mod test_vectors;
pub mod handshake_vectors;
pub mod negative;
pub mod version_negotiation;
pub mod protocol_compliance;
