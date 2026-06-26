//! Fuzz target for CBOR decoding.
//!
//! Feeds arbitrary bytes into the CBOR decoder to find panics or crashes.
//! The decoder should never panic on any input — it should always return
//! an error for invalid data.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The CBOR decoder must never panic on any input.
    let _ = aafp_cbor::decode(data);
});
