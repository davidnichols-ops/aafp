//! Fuzz target for AgentRecord CBOR parsing.
//!
//! Feeds arbitrary bytes as CBOR into the AgentRecord parser.
//! The parser must handle invalid CBOR without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((value, _)) = aafp_cbor::decode(data) {
        let _ = aafp_identity::identity_v1::AgentRecord::from_cbor(&value);
    }
});
