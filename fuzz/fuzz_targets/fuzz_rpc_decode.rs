//! Fuzz target for RPC message decoding.
//!
//! Feeds arbitrary bytes as CBOR into the RPC message parsers.
//! All parsers must handle invalid CBOR without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((value, _)) = aafp_cbor::decode(data) {
        let _ = aafp_messaging::rpc_v1::RpcRequest::from_cbor(&value);
        let _ = aafp_messaging::rpc_v1::RpcResponse::from_cbor(&value);
    }
    // Also try direct decode from raw bytes
    let _ = aafp_messaging::rpc_v1::RpcRequest::decode(data);
    let _ = aafp_messaging::rpc_v1::RpcResponse::decode(data);
});
