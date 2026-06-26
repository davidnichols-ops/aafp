//! Conformance tests for RFC-0004: Discovery.
//!
//! Covers:
//! - §3: Bootstrap discovery protocol
//! - §3.3: RPC methods (announce, lookup)
//! - §3.4: Bootstrap node requirements (rate limits, max records)
//! - §4: Capability DHT operations

use aafp_crypto::{MlDsa65, SignatureScheme};
use aafp_discovery::discovery_v1::{
    AnnounceParams, AnnounceResult, CapabilityDht, LookupParams, LookupResult,
    DEFAULT_LIMIT_AUTH, DEFAULT_LIMIT_UNAUTH, MAX_RECORDS, METHOD_ANNOUNCE, METHOD_LOOKUP,
    RATE_LIMIT_ANNOUNCE, RATE_LIMIT_LOOKUP,
};
use aafp_identity::identity_v1::{AgentRecord, CapabilityDescriptor};

fn make_test_record(capabilities: Vec<&str>) -> AgentRecord {
    let (pk, sk) = MlDsa65::keypair();
    let now = 1700000000u64;
    let mut record = AgentRecord::new(
        &pk.0,
        capabilities
            .iter()
            .map(|c| CapabilityDescriptor::new(*c))
            .collect(),
        vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
        now,
        now + 86400,
        1,
    );
    record.sign(&sk);
    record
}

/// R4-001: aafp.discovery.announce method name MUST be correct.
#[test]
fn test_r4_001_announce_method_name() {
    assert_eq!(METHOD_ANNOUNCE, "aafp.discovery.announce");
}

/// R4-002: aafp.discovery.lookup method name MUST be correct.
#[test]
fn test_r4_002_lookup_method_name() {
    assert_eq!(METHOD_LOOKUP, "aafp.discovery.lookup");
}

/// R4-003: AnnounceParams MUST use integer key 1 for record.
#[test]
fn test_r4_003_announce_params_key() {
    let record = make_test_record(vec!["inference"]);
    let params = AnnounceParams::new(record);
    let cbor = params.to_cbor();
    assert!(aafp_cbor::int_map_get(&cbor, 1).is_some(), "key 1 must be record");
}

/// R4-004: AnnounceResult MUST use integer key 1 for peers array.
#[test]
fn test_r4_004_announce_result_key() {
    let result = AnnounceResult::new(vec![]);
    let cbor = result.to_cbor();
    assert!(aafp_cbor::int_map_get(&cbor, 1).is_some(), "key 1 must be peers");
}

/// R4-005: LookupParams MUST use integer key 1 for capability, 2 for limit.
#[test]
fn test_r4_005_lookup_params_keys() {
    let params = LookupParams::new("inference").with_limit(10);
    let cbor = params.to_cbor();
    assert!(aafp_cbor::int_map_get(&cbor, 1).is_some(), "key 1 must be capability");
    assert!(aafp_cbor::int_map_get(&cbor, 2).is_some(), "key 2 must be limit");
}

/// R4-006: Default unauthenticated lookup limit MUST be 5.
#[test]
fn test_r4_006_default_unauth_limit() {
    assert_eq!(DEFAULT_LIMIT_UNAUTH, 5);
}

/// R4-007: Default authenticated lookup limit MUST be 10.
#[test]
fn test_r4_007_default_auth_limit() {
    assert_eq!(DEFAULT_LIMIT_AUTH, 10);
}

/// R4-008: Max records MUST be 100,000.
#[test]
fn test_r4_008_max_records() {
    assert_eq!(MAX_RECORDS, 100_000);
}

/// R4-009: Announce rate limit MUST be 60 seconds.
#[test]
fn test_r4_009_announce_rate_limit() {
    assert_eq!(RATE_LIMIT_ANNOUNCE, 60);
}

/// R4-010: Lookup rate limit MUST be 60 seconds.
#[test]
fn test_r4_010_lookup_rate_limit() {
    assert_eq!(RATE_LIMIT_LOOKUP, 60);
}

/// R4-020: DHT put MUST index by each capability.
#[test]
fn test_r4_020_dht_indexes_all_capabilities() {
    let mut dht = CapabilityDht::new();
    let record = make_test_record(vec!["inference", "translation", "vision"]);
    dht.put(record);

    assert_eq!(dht.get("inference").len(), 1);
    assert_eq!(dht.get("translation").len(), 1);
    assert_eq!(dht.get("vision").len(), 1);
    assert_eq!(dht.capability_count(), 3);
}

/// R4-021: DHT get MUST return all records matching capability.
#[test]
fn test_r4_021_dht_get_returns_all_matches() {
    let mut dht = CapabilityDht::new();
    dht.put(make_test_record(vec!["inference"]));
    dht.put(make_test_record(vec!["inference"]));
    dht.put(make_test_record(vec!["translation"]));

    assert_eq!(dht.get("inference").len(), 2);
    assert_eq!(dht.get("translation").len(), 1);
}

/// R4-022: DHT put MUST replace existing record if newer.
#[test]
fn test_r4_022_dht_replaces_newer() {
    let mut dht = CapabilityDht::new();
    let (pk, sk) = MlDsa65::keypair();
    let now = 1700000000u64;

    let mut r1 = AgentRecord::new(&pk.0, vec![CapabilityDescriptor::new("inference")], vec![], now, now + 86400, 1);
    r1.sign(&sk);
    assert!(dht.put(r1));

    let mut r2 = AgentRecord::new(&pk.0, vec![CapabilityDescriptor::new("inference")], vec![], now + 100, now + 86400, 1);
    r2.sign(&sk);
    assert!(dht.put(r2));

    assert_eq!(dht.len(), 1, "record should be replaced, not duplicated");
}

/// R4-023: DHT MUST reject older records.
#[test]
fn test_r4_023_dht_rejects_older() {
    let mut dht = CapabilityDht::new();
    let (pk, sk) = MlDsa65::keypair();
    let now = 1700000000u64;

    let mut r1 = AgentRecord::new(&pk.0, vec![], vec![], now + 100, now + 86400, 1);
    r1.sign(&sk);
    assert!(dht.put(r1));

    let mut r2 = AgentRecord::new(&pk.0, vec![], vec![], now, now + 86400, 1);
    r2.sign(&sk);
    assert!(!dht.put(r2), "older record must be rejected");
}

/// R4-024: DHT MUST evict expired records.
#[test]
fn test_r4_024_dht_evicts_expired() {
    let mut dht = CapabilityDht::new();
    let (pk, sk) = MlDsa65::keypair();
    let now = 1700000000u64;

    let mut r1 = AgentRecord::new(&pk.0, vec![CapabilityDescriptor::new("inference")], vec![], now, now + 100, 1);
    r1.sign(&sk);
    dht.put(r1);

    assert_eq!(dht.get("inference").len(), 1);
    let evicted = dht.evict_expired(now + 200);
    assert_eq!(evicted, 1);
    assert_eq!(dht.get("inference").len(), 0);
}

/// R4-025: AnnounceParams CBOR roundtrip must preserve record.
#[test]
fn test_r4_025_announce_params_roundtrip() {
    let record = make_test_record(vec!["inference"]);
    let params = AnnounceParams::new(record.clone());

    let cbor = params.to_cbor();
    let encoded = aafp_cbor::encode(&cbor).unwrap();
    let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
    let params2 = AnnounceParams::from_cbor(&decoded).unwrap();

    assert_eq!(params2.record.agent_id, record.agent_id);
    assert_eq!(params2.record.public_key, record.public_key);
}

/// R4-026: LookupParams CBOR roundtrip must preserve fields.
#[test]
fn test_r4_026_lookup_params_roundtrip() {
    let params = LookupParams::new("inference").with_limit(10);
    let cbor = params.to_cbor();
    let encoded = aafp_cbor::encode(&cbor).unwrap();
    let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
    let params2 = LookupParams::from_cbor(&decoded).unwrap();

    assert_eq!(params2.capability, "inference");
    assert_eq!(params2.limit, Some(10));
}
