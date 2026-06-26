//! Fuzz target for frame decoding.
//!
//! Feeds arbitrary bytes into the frame decoder to find panics or crashes.
//! The decoder should handle all malformed inputs gracefully.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The frame decoder must never panic on any input.
    let _ = aafp_messaging::decode_frame(data);
});
