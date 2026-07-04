//! End-to-end trust scenario testing (Track P8, RFC 0011).
//!
//! Tests the complete trust lifecycle across all 8 scenarios:
//! 1. TOFU: A connects to B for the first time → trust on first use
//! 2. Directory: A publishes to directory, B looks up A → trusted
//! 3. WoT: A signs B, C trusts A → C trusts B (transitive)
//! 4. CA: CA signs A, B trusts CA → B trusts A
//! 5. Key rotation: A rotates key, B receives rotation → B trusts new key
//! 6. Revocation: A is revoked, B receives CRL → B rejects A
//! 7. Revoked + rotated: A's old key is revoked, A's new key is trusted
//! 8. MITM detection: Attacker presents wrong key → TrustManager rejects

use aafp_identity::ca_certificate::CaCertificate;
use aafp_identity::identity_v1::{AgentId, AgentRecord};
use aafp_identity::key_directory::KeyDirectory;
use aafp_identity::key_rotation::KeyRotationRecord;
use aafp_identity::keypair::AgentKeypair;
use aafp_identity::revocation::RevocationList;
use aafp_identity::trust_manager::{
    TrustManager, TrustPolicy, TrustResult, TrustSource, TrustSuggestion,
};
use aafp_identity::web_of_trust::{TrustSignature, TRUST_LEVEL_FULL, TRUST_LEVEL_MARGINAL};

const NOW: u64 = 1_000_000;
const VALIDITY: u64 = 86400; // 24 hours

fn make_keypair() -> AgentKeypair {
    AgentKeypair::generate()
}

fn make_agent_id(kp: &AgentKeypair) -> AgentId {
    AgentId::from_public_key(&kp.public_key)
}

fn make_record(kp: &AgentKeypair) -> AgentRecord {
    let mut record = AgentRecord::new(
        &kp.public_key,
        vec![],
        vec![],
        NOW,
        NOW + VALIDITY,
        aafp_identity::identity_v1::KEY_ALG_ML_DSA_65,
    );
    record.sign(&kp.secret_key().unwrap());
    record
}

/// Scenario 1: TOFU — A connects to B for the first time.
#[test]
fn test_scenario_1_tofu() {
    let a = make_keypair();
    let b = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);

    let tm = TrustManager::new(a_id);
    let result = tm.verify_peer(&b_id, &b.public_key, None, NOW);

    // Should be Unknown with Tofu suggestion
    match &result {
        TrustResult::Unknown { suggestion } => {
            assert_eq!(*suggestion, TrustSuggestion::Tofu);
        }
        _ => panic!("expected Unknown for first connection"),
    }

    // Permissive policy accepts TOFU
    let tm_permissive = TrustManager::new(a_id).with_policy(TrustPolicy::Permissive);
    assert!(tm_permissive.should_accept(&result));

    // Strict policy rejects
    let tm_strict = TrustManager::new(a_id).with_policy(TrustPolicy::Strict);
    assert!(!tm_strict.should_accept(&result));

    // Accept TOFU → now directly trusted
    tm.accept_tofu(b_id, b.public_key.clone());
    let result2 = tm.verify_peer(&b_id, &b.public_key, None, NOW);
    match result2 {
        TrustResult::Trusted { source, .. } => assert_eq!(source, TrustSource::Direct),
        _ => panic!("expected Trusted after TOFU acceptance"),
    }
}

/// Scenario 2: Directory — A publishes to directory, B looks up A.
#[test]
fn test_scenario_2_directory() {
    let a = make_keypair();
    let b = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);

    // A publishes its record to the directory
    let mut dir = KeyDirectory::new();
    let a_record = make_record(&a);
    dir.publish(a_record, NOW).unwrap();

    // B has the directory configured
    let tm = TrustManager::new(b_id).with_directory(dir);

    // B verifies A → should be Trusted via Directory
    let result = tm.verify_peer(&a_id, &a.public_key, None, NOW);
    match result {
        TrustResult::Trusted { source, level } => {
            assert_eq!(source, TrustSource::Directory);
            assert_eq!(level, 2); // Full
        }
        _ => panic!("expected Trusted from Directory"),
    }
}

/// Scenario 3: WoT — A signs B, C trusts A → C trusts B (transitive).
#[test]
fn test_scenario_3_wot_transitive() {
    let a = make_keypair();
    let b = make_keypair();
    let c = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);
    let c_id = make_agent_id(&c);

    // C's TrustManager with WoT
    let tm = TrustManager::new(c_id);

    // C directly trusts A (Full)
    let sig_ca = TrustSignature::new(
        c_id,
        a_id,
        &a.public_key,
        TRUST_LEVEL_FULL,
        NOW + VALIDITY,
        &c.secret_key().unwrap(),
    )
    .unwrap();
    tm.wot().add_trust_signature(sig_ca);

    // A trusts B (Full)
    let sig_ab = TrustSignature::new(
        a_id,
        b_id,
        &b.public_key,
        TRUST_LEVEL_FULL,
        NOW + VALIDITY,
        &a.secret_key().unwrap(),
    )
    .unwrap();
    tm.wot().add_trust_signature(sig_ab);

    // C verifies B → one hop: Marginal
    let result = tm.verify_peer(&b_id, &b.public_key, None, NOW);
    match result {
        TrustResult::Trusted { source, level } => {
            assert_eq!(source, TrustSource::WebOfTrust);
            assert_eq!(level, TRUST_LEVEL_MARGINAL);
        }
        _ => panic!("expected Trusted from WoT (transitive)"),
    }
}

/// Scenario 4: CA — CA signs A, B trusts CA → B trusts A.
#[test]
fn test_scenario_4_ca() {
    let ca = make_keypair();
    let a = make_keypair();
    let b = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);

    let tm = TrustManager::new(b_id);
    tm.add_trusted_ca(ca.public_key.clone());

    // CA signs A
    let cert = CaCertificate::issue(
        a_id,
        &a.public_key,
        "Test CA",
        &ca.public_key,
        &ca.secret_key().unwrap(),
        1,
        NOW,
        NOW + VALIDITY,
        vec!["inference".into()],
    );

    // B verifies A with the cert → Trusted via CA
    let result = tm.verify_peer(&a_id, &a.public_key, Some(&cert), NOW);
    match result {
        TrustResult::Trusted { source, level } => {
            assert_eq!(source, TrustSource::CertificateAuthority);
            assert_eq!(level, 2); // Full
        }
        _ => panic!("expected Trusted from CA"),
    }
}

/// Scenario 5: Key rotation — A rotates key, B receives rotation.
#[test]
fn test_scenario_5_key_rotation() {
    let a_old = make_keypair();
    let a_new = make_keypair();
    let b = make_keypair();
    let a_old_id = make_agent_id(&a_old);
    let a_new_id = make_agent_id(&a_new);
    let b_id = make_agent_id(&b);

    // B had direct trust in A's old key
    let tm = TrustManager::new(b_id);
    tm.add_direct_trust(a_old_id, a_old.public_key.clone());

    // A rotates key
    let rotation = KeyRotationRecord::new(
        a_old_id,
        a_new_id,
        &a_new.public_key,
        NOW,
        &a_old.secret_key().unwrap(),
        &a_new.secret_key().unwrap(),
    );

    // B verifies the rotation record
    let old_pk = a_old.public_key().unwrap();
    assert!(rotation.verify(&old_pk, NOW).is_ok());

    // B updates trust: remove old, add new
    // (In a full implementation, this would be automatic upon receiving the rotation)
    tm.add_direct_trust(a_new_id, a_new.public_key.clone());

    // B can now verify A's new key
    let result = tm.verify_peer(&a_new_id, &a_new.public_key, None, NOW);
    match result {
        TrustResult::Trusted { source, .. } => assert_eq!(source, TrustSource::Direct),
        _ => panic!("expected Trusted for rotated key"),
    }
}

/// Scenario 6: Revocation — A is revoked, B receives CRL.
#[test]
fn test_scenario_6_revocation() {
    let a = make_keypair();
    let b = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);

    let tm = TrustManager::new(b_id);

    // B had direct trust in A
    tm.add_direct_trust(a_id, a.public_key.clone());

    // A is revoked
    let mut crl = RevocationList::new(NOW, 3600);
    crl.revoke(
        a_id,
        NOW,
        Some("compromised".into()),
        a_id,
        &a.secret_key().unwrap(),
    );
    tm.revocation_store().lock().unwrap().add_crl(crl);

    // B rejects A
    let result = tm.verify_peer(&a_id, &a.public_key, None, NOW);
    assert!(matches!(result, TrustResult::Revoked { .. }));
    assert!(!tm.should_accept(&result));
}

/// Scenario 7: Revoked + rotated — A's old key revoked, new key trusted.
#[test]
fn test_scenario_7_revoked_and_rotated() {
    let a_old = make_keypair();
    let a_new = make_keypair();
    let b = make_keypair();
    let a_old_id = make_agent_id(&a_old);
    let a_new_id = make_agent_id(&a_new);
    let b_id = make_agent_id(&b);

    let tm = TrustManager::new(b_id);

    // A rotates key
    let rotation = KeyRotationRecord::new(
        a_old_id,
        a_new_id,
        &a_new.public_key,
        NOW,
        &a_old.secret_key().unwrap(),
        &a_new.secret_key().unwrap(),
    );

    // Old key is revoked (as part of rotation)
    let crl =
        rotation.create_revocation_crl(&a_old.secret_key().unwrap(), 3600, Some("rotated".into()));
    tm.revocation_store().lock().unwrap().add_crl(crl);

    // B trusts A's new key (via rotation verification)
    let old_pk = a_old.public_key().unwrap();
    assert!(rotation.verify(&old_pk, NOW).is_ok());
    tm.add_direct_trust(a_new_id, a_new.public_key.clone());

    // Old key is rejected (revoked)
    let result_old = tm.verify_peer(&a_old_id, &a_old.public_key, None, NOW);
    assert!(matches!(result_old, TrustResult::Revoked { .. }));

    // New key is trusted
    let result_new = tm.verify_peer(&a_new_id, &a_new.public_key, None, NOW);
    assert!(matches!(result_new, TrustResult::Trusted { .. }));
}

/// Scenario 8: MITM detection — Attacker presents wrong key.
#[test]
fn test_scenario_8_mitm_detection() {
    let a = make_keypair();
    let attacker = make_keypair();
    let b = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);

    // B has A's key in direct trust cache
    let tm = TrustManager::new(b_id);
    tm.add_direct_trust(a_id, a.public_key.clone());

    // Attacker presents their key but claims to be A
    let result = tm.verify_peer(&a_id, &attacker.public_key, None, NOW);

    // Should be Untrusted (key mismatch)
    match result {
        TrustResult::Untrusted { ref reason } => {
            assert!(reason.contains("mismatch"));
        }
        _ => panic!("expected Untrusted for MITM"),
    }
    assert!(!tm.should_accept(&result));
}

/// Test: revocation overrides all other trust sources.
#[test]
fn test_revocation_overrides_wot() {
    let a = make_keypair();
    let b = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);

    let tm = TrustManager::new(b_id);

    // B trusts A via WoT
    let sig = TrustSignature::new(
        b_id,
        a_id,
        &a.public_key,
        TRUST_LEVEL_FULL,
        NOW + VALIDITY,
        &b.secret_key().unwrap(),
    )
    .unwrap();
    tm.wot().add_trust_signature(sig);

    // Revoke A
    let mut crl = RevocationList::new(NOW, 3600);
    crl.revoke(
        a_id,
        NOW,
        Some("compromised".into()),
        a_id,
        &a.secret_key().unwrap(),
    );
    tm.revocation_store().lock().unwrap().add_crl(crl);

    let result = tm.verify_peer(&a_id, &a.public_key, None, NOW);
    assert!(matches!(result, TrustResult::Revoked { .. }));
}

/// Test: revocation overrides CA trust.
#[test]
fn test_revocation_overrides_ca() {
    let ca = make_keypair();
    let a = make_keypair();
    let b = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);

    let tm = TrustManager::new(b_id);
    tm.add_trusted_ca(ca.public_key.clone());

    let cert = CaCertificate::issue(
        a_id,
        &a.public_key,
        "Test CA",
        &ca.public_key,
        &ca.secret_key().unwrap(),
        1,
        NOW,
        NOW + VALIDITY,
        vec!["inference".into()],
    );

    // Revoke A
    let mut crl = RevocationList::new(NOW, 3600);
    crl.revoke(
        a_id,
        NOW,
        Some("compromised".into()),
        a_id,
        &a.secret_key().unwrap(),
    );
    tm.revocation_store().lock().unwrap().add_crl(crl);

    let result = tm.verify_peer(&a_id, &a.public_key, Some(&cert), NOW);
    assert!(matches!(result, TrustResult::Revoked { .. }));
}

/// Test: expired WoT signature is ignored.
#[test]
fn test_expired_wot_signature_ignored() {
    let a = make_keypair();
    let b = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);

    let tm = TrustManager::new(b_id);

    // B signs A with an expired signature
    let sig = TrustSignature::new(
        b_id,
        a_id,
        &a.public_key,
        TRUST_LEVEL_FULL,
        NOW - 1, // Expired
        &b.secret_key().unwrap(),
    )
    .unwrap();
    tm.wot().add_trust_signature(sig);

    let result = tm.verify_peer(&a_id, &a.public_key, None, NOW);
    // Should not be Trusted (expired signature ignored)
    assert!(!matches!(result, TrustResult::Trusted { .. }));
}

/// Test: expired CA certificate is rejected.
#[test]
fn test_expired_ca_cert_rejected() {
    let ca = make_keypair();
    let a = make_keypair();
    let b = make_keypair();
    let a_id = make_agent_id(&a);
    let b_id = make_agent_id(&b);

    let tm = TrustManager::new(b_id);
    tm.add_trusted_ca(ca.public_key.clone());

    // Issue cert that's already expired
    let cert = CaCertificate::issue(
        a_id,
        &a.public_key,
        "Test CA",
        &ca.public_key,
        &ca.secret_key().unwrap(),
        1,
        NOW - 7200,
        NOW - 3600, // Expired
        vec!["inference".into()],
    );

    let result = tm.verify_peer(&a_id, &a.public_key, Some(&cert), NOW);
    // CA verification fails (expired) → falls through to Unknown
    assert!(matches!(result, TrustResult::Unknown { .. }));
}
