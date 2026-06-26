//! Fuzz target for handshake CBOR parsing.
//!
//! Feeds arbitrary bytes as CBOR into the handshake message parsers.
//! All parsers must handle invalid CBOR without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First try to decode as CBOR
    if let Ok((value, _)) = aafp_cbor::decode(data) {
        // Try to parse as ClientHello
        let _ = aafp_crypto::handshake_v1::ClientHello::from_cbor(&value);
        // Try to parse as ServerHello
        let _ = aafp_crypto::handshake_v1::ServerHello::from_cbor(&value);
        // Try to parse as ClientFinished
        let _ = aafp_crypto::handshake_v1::ClientFinished::from_cbor(&value);
    }
});
