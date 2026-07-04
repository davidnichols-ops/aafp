//! Fuzz target for DHT capability store and record parsing.
//!
//! Feeds arbitrary CBOR values to the DHT record parsers and exercises
//! the in-memory CapabilityDht with fuzzed records and capability strings.
//! All operations must complete without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((value, _)) = aafp_cbor::decode(data) {
        // Try parsing AnnounceParams, AnnounceResult, LookupParams, LookupResult
        let _ = aafp_discovery::AnnounceParams::from_cbor(&value);
        let _ = aafp_discovery::AnnounceResult::from_cbor(&value);
        let _ = aafp_discovery::LookupParams::from_cbor(&value);
        let _ = aafp_discovery::LookupResult::from_cbor(&value);

        // Try parsing as AgentRecord and inserting into DHT
        if let Ok(record) = aafp_identity::identity_v1::AgentRecord::from_cbor(&value) {
            let mut dht = aafp_discovery::CapabilityDhtV1::new();
            let _ = dht.put(record.clone());
            // Try looking up by each capability name in the record
            for cap in &record.capabilities {
                let _ = dht.get(&cap.name);
            }
            // Try looking up by the agent ID
            let _ = dht.get_by_id(&record.agent_id);
        }
    }
});
