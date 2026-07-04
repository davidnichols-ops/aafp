//! Fuzz target for discovery RPC request parsing.
//!
//! Feeds arbitrary CBOR values to the discovery params/result parsers.
//! All parsers must handle invalid CBOR without panicking.
//!
//! Note: The DiscoveryRpcHandler::handle_request is async and cannot be
//! called directly from a libfuzzer target. We fuzz the synchronous CBOR
//! parsing paths instead.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((value, _)) = aafp_cbor::decode(data) {
        // Try parsing all discovery message types from the value
        let _ = aafp_discovery::AnnounceParams::from_cbor(&value);
        let _ = aafp_discovery::AnnounceResult::from_cbor(&value);
        let _ = aafp_discovery::LookupParams::from_cbor(&value);
        let _ = aafp_discovery::LookupResult::from_cbor(&value);
    }
});
