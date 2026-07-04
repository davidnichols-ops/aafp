//! Fuzz target for relay RPC request handling.
//!
//! Feeds arbitrary CBOR values as method + params to the relay RPC
//! handler. The handler must handle all inputs without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to decode as CBOR first
    if let Ok((value, _)) = aafp_cbor::decode(data) {
        // Try parsing each relay params type from the value
        let _ = aafp_nat::relay_v1::ReserveParams::from_cbor(&value);
        let _ = aafp_nat::relay_v1::RenewParams::from_cbor(&value);
        let _ = aafp_nat::relay_v1::CancelParams::from_cbor(&value);
        let _ = aafp_nat::relay_v1::ConnectParams::from_cbor(&value);
        let _ = aafp_nat::relay_v1::ReserveResult::from_cbor(&value);
        let _ = aafp_nat::relay_v1::ConnectResult::from_cbor(&value);

        // Try the full RPC handler with a dummy agent ID and method.
        // AgentId at the crate root is a type alias for [u8; 32].
        let handler = aafp_nat::relay_v1::RelayV1RpcHandler::with_defaults();
        let dummy_id: aafp_identity::AgentId = [0u8; 32];
        for method in &[
            aafp_nat::relay_v1::METHOD_RESERVE,
            aafp_nat::relay_v1::METHOD_RENEW,
            aafp_nat::relay_v1::METHOD_CANCEL,
            aafp_nat::relay_v1::METHOD_CONNECT,
            "aafp.evil.method",
            "",
        ] {
            let _ = handler.handle_request(method, &value, &dummy_id);
        }
    }
});
