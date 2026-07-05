//! TrustManager: unified API for trust decisions (RFC 0011 §8).
//!
//! Combines all trust sources into a single API:
//! 1. Direct trust (connected before, key cached)
//! 2. WoT trust (transitive trust from peers)
//! 3. CA trust (certificate from a trusted CA)
//! 4. Directory trust (record from a trusted directory)
//! 5. Revocation check (is the key revoked?)
//!
//! Called after the handshake completes, before the application begins
//! exchanging data.

use crate::ca_certificate::{CaCertificate, CaVerifier};
use crate::identity_v1::AgentId;
use crate::key_directory::KeyDirectory;
use crate::revocation::RevocationStore;
use crate::web_of_trust::{WebOfTrust, TRUST_LEVEL_FULL, TRUST_LEVEL_MARGINAL};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The source of a trust decision (RFC 0011 §8.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustSource {
    /// Direct trust (connected before, key cached).
    Direct,
    /// Web of Trust (transitive trust from peers).
    WebOfTrust,
    /// CA certificate (verified against trusted CA).
    CertificateAuthority,
    /// Key directory (verified against directory record).
    Directory,
    /// Trust On First Use (no other source available).
    Tofu,
}

/// A suggestion for when trust is unknown (RFC 0011 §8.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustSuggestion {
    /// Trust on first use (show key fingerprint to user).
    Tofu,
    /// Look up in key directory.
    QueryDirectory,
    /// Ask a mutual contact to sign.
    RequestWotSignature,
    /// Ask peer to get a CA certificate.
    RequestCaCert,
}

/// The result of a trust verification (RFC 0011 §8.2).
#[derive(Clone, Debug)]
pub enum TrustResult {
    /// The peer is trusted.
    Trusted {
        /// Source of the trust.
        source: TrustSource,
        /// Trust level (0-3).
        level: u8,
    },
    /// The peer is not trusted (verification failed).
    Untrusted {
        /// Reason for rejection.
        reason: String,
    },
    /// The peer's key is revoked.
    Revoked {
        /// Reason for revocation.
        reason: String,
    },
    /// No trust information available.
    Unknown {
        /// Suggestion for establishing trust.
        suggestion: TrustSuggestion,
    },
}

/// Trust policy (RFC 0011 §8.6).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum TrustPolicy {
    /// Reject Unknown and Untrusted. Only accept Trusted.
    Strict,
    /// Accept Trusted, reject Untrusted and Revoked, prompt for Unknown.
    #[default]
    Cautious,
    /// Accept Trusted and Unknown (TOFU), reject Revoked.
    Permissive,
}

/// TrustManager: combines all trust sources (RFC 0011 §8).
pub struct TrustManager {
    /// The agent's own AgentId.
    own_agent_id: AgentId,
    /// Direct-trust cache: AgentId → public key (connected before).
    direct_cache: Mutex<HashMap<AgentId, Vec<u8>>>,
    /// Web of Trust.
    wot: Mutex<WebOfTrust>,
    /// CA verifier.
    ca_verifier: Mutex<CaVerifier>,
    /// Key directory (optional).
    directory: Mutex<Option<KeyDirectory>>,
    /// Revocation store.
    revocation_store: Arc<Mutex<RevocationStore>>,
    /// Trust policy.
    policy: TrustPolicy,
}

impl TrustManager {
    /// Create a new TrustManager.
    pub fn new(own_agent_id: AgentId) -> Self {
        let mut wot = WebOfTrust::new();
        wot.set_own_agent_id(own_agent_id);
        Self {
            own_agent_id,
            direct_cache: Mutex::new(HashMap::new()),
            wot: Mutex::new(wot),
            ca_verifier: Mutex::new(CaVerifier::new()),
            directory: Mutex::new(None),
            revocation_store: Arc::new(Mutex::new(RevocationStore::new())),
            policy: TrustPolicy::default(),
        }
    }

    /// Set the trust policy.
    pub fn with_policy(mut self, policy: TrustPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Set the key directory.
    pub fn with_directory(self, directory: KeyDirectory) -> Self {
        *self.directory.lock().unwrap() = Some(directory);
        self
    }

    /// Add a trusted root CA key.
    pub fn add_trusted_ca(&self, public_key: Vec<u8>) {
        self.ca_verifier
            .lock()
            .unwrap()
            .add_trusted_root(public_key);
    }

    /// Add a direct-trust entry (peer we've connected to before).
    pub fn add_direct_trust(&self, agent_id: AgentId, public_key: Vec<u8>) {
        self.direct_cache
            .lock()
            .unwrap()
            .insert(agent_id, public_key);
    }

    /// Get a reference to the WoT (for adding trust signatures).
    pub fn wot(&self) -> std::sync::MutexGuard<'_, WebOfTrust> {
        self.wot.lock().unwrap()
    }

    /// Get a reference to the revocation store.
    pub fn revocation_store(&self) -> &Arc<Mutex<RevocationStore>> {
        &self.revocation_store
    }

    /// Verify a peer (RFC 0011 §8.5).
    ///
    /// Verification order:
    /// 1. Revocation check (highest priority)
    /// 2. Direct trust
    /// 3. CA certificate
    /// 4. Web of Trust
    /// 5. Directory
    /// 6. Unknown
    pub fn verify_peer(
        &self,
        agent_id: &AgentId,
        public_key: &[u8],
        ca_cert: Option<&CaCertificate>,
        now: u64,
    ) -> TrustResult {
        // Step 1: Revocation check (highest priority)
        if self.revocation_store.lock().unwrap().is_revoked(agent_id) {
            return TrustResult::Revoked {
                reason: "agent_id is in revocation store".into(),
            };
        }

        // Step 2: Direct trust
        if let Some(cached_pk) = self.direct_cache.lock().unwrap().get(agent_id) {
            if cached_pk == public_key {
                return TrustResult::Trusted {
                    source: TrustSource::Direct,
                    level: crate::web_of_trust::TRUST_LEVEL_ULTIMATE,
                };
            } else {
                return TrustResult::Untrusted {
                    reason: "public key mismatch with cached direct trust".into(),
                };
            }
        }

        // Step 3: CA certificate
        if let Some(cert) = ca_cert {
            let verifier = self.ca_verifier.lock().unwrap();
            match verifier.verify_certificate(
                cert,
                now,
                Some(&self.revocation_store.lock().unwrap()),
            ) {
                Ok(()) => {
                    return TrustResult::Trusted {
                        source: TrustSource::CertificateAuthority,
                        level: TRUST_LEVEL_FULL,
                    };
                }
                Err(e) => {
                    // CA verification failed — fall through to other sources
                    let _ = e;
                }
            }
        }

        // Step 4: Web of Trust
        let wot_level = self.wot.lock().unwrap().trust_level(agent_id, now);
        if wot_level >= TRUST_LEVEL_MARGINAL {
            return TrustResult::Trusted {
                source: TrustSource::WebOfTrust,
                level: wot_level,
            };
        }

        // Step 5: Directory
        if let Some(dir) = self.directory.lock().unwrap().as_ref() {
            if let Some(record) = dir.lookup(agent_id) {
                // Verify the record matches
                if record.public_key == public_key {
                    // Verify the record's signature
                    if record.verify(now).is_ok() {
                        return TrustResult::Trusted {
                            source: TrustSource::Directory,
                            level: TRUST_LEVEL_FULL,
                        };
                    }
                } else {
                    return TrustResult::Untrusted {
                        reason: "public key mismatch with directory record".into(),
                    };
                }
            }
        }

        // Step 6: Unknown
        let suggestion = if self.directory.lock().unwrap().is_some() {
            TrustSuggestion::QueryDirectory
        } else if !self.wot.lock().unwrap().all_signatures().is_empty() {
            TrustSuggestion::RequestWotSignature
        } else {
            TrustSuggestion::Tofu
        };

        TrustResult::Unknown { suggestion }
    }

    /// Decide whether to accept a peer based on the trust result and policy.
    pub fn should_accept(&self, result: &TrustResult) -> bool {
        match (&self.policy, result) {
            (_, TrustResult::Trusted { .. }) => true,
            (_, TrustResult::Revoked { .. }) => false,
            (TrustPolicy::Strict, TrustResult::Untrusted { .. }) => false,
            (TrustPolicy::Strict, TrustResult::Unknown { .. }) => false,
            (TrustPolicy::Cautious, TrustResult::Untrusted { .. }) => false,
            (TrustPolicy::Cautious, TrustResult::Unknown { .. }) => false, // Would prompt in interactive mode
            (TrustPolicy::Permissive, TrustResult::Untrusted { .. }) => false,
            (TrustPolicy::Permissive, TrustResult::Unknown { .. }) => true, // TOFU
        }
    }

    /// Accept a peer via TOFU (add to direct-trust cache).
    pub fn accept_tofu(&self, agent_id: AgentId, public_key: Vec<u8>) {
        self.add_direct_trust(agent_id, public_key);
    }

    /// Get the agent's own AgentId.
    pub fn own_agent_id(&self) -> &AgentId {
        &self.own_agent_id
    }

    /// Get the trust policy.
    pub fn policy(&self) -> &TrustPolicy {
        &self.policy
    }

    /// Count of directly trusted peers.
    pub fn direct_trust_count(&self) -> usize {
        self.direct_cache.lock().unwrap().len()
    }

    /// Count of trusted CA roots.
    pub fn trusted_ca_count(&self) -> usize {
        self.ca_verifier.lock().unwrap().trusted_root_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_v1::AgentRecord;
    use crate::keypair::AgentKeypair;
    use crate::web_of_trust::{TrustSignature, TRUST_LEVEL_ULTIMATE};

    fn make_keypair() -> AgentKeypair {
        AgentKeypair::generate()
    }

    #[test]
    fn test_trust_manager_direct_trust() {
        let a = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b = make_keypair();
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id);
        tm.add_direct_trust(b_id, b.public_key.clone());

        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        match result {
            TrustResult::Trusted { source, level } => {
                assert_eq!(source, TrustSource::Direct);
                assert_eq!(level, TRUST_LEVEL_ULTIMATE);
            }
            _ => panic!("expected Trusted"),
        }
    }

    #[test]
    fn test_trust_manager_revoked() {
        let a = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b = make_keypair();
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id);

        // Revoke B
        let mut crl = crate::revocation::RevocationList::new(1_000_000, 3600);
        crl.revoke(
            b_id,
            1_000_000,
            Some("compromised".into()),
            b_id,
            &b.secret_key().unwrap(),
        );
        tm.revocation_store().lock().unwrap().add_crl(crl);

        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        assert!(matches!(result, TrustResult::Revoked { .. }));
        assert!(!tm.should_accept(&result));
    }

    #[test]
    fn test_trust_manager_wot_trust() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id);

        // A signs B at Full trust
        let sig = TrustSignature::new(
            a_id,
            b_id,
            &b.public_key,
            TRUST_LEVEL_FULL,
            2_000_000,
            &a.secret_key().unwrap(),
        )
        .unwrap();
        tm.wot().add_trust_signature(sig);

        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        match result {
            TrustResult::Trusted { source, level } => {
                assert_eq!(source, TrustSource::WebOfTrust);
                assert_eq!(level, TRUST_LEVEL_FULL);
            }
            _ => panic!("expected Trusted from WoT"),
        }
    }

    #[test]
    fn test_trust_manager_ca_trust() {
        let ca = make_keypair();
        let a = make_keypair();
        let agent = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let agent_id = AgentId::from_public_key(&agent.public_key);
        let now = 1_000_000u64;

        let tm = TrustManager::new(a_id);
        tm.add_trusted_ca(ca.public_key.clone());

        let cert = CaCertificate::issue(
            agent_id,
            &agent.public_key,
            "Test CA",
            &ca.public_key,
            &ca.secret_key().unwrap(),
            1,
            now,
            now + 3600,
            vec!["inference".into()],
        );

        let result = tm.verify_peer(&agent_id, &agent.public_key, Some(&cert), now);
        match result {
            TrustResult::Trusted { source, level } => {
                assert_eq!(source, TrustSource::CertificateAuthority);
                assert_eq!(level, TRUST_LEVEL_FULL);
            }
            _ => panic!("expected Trusted from CA"),
        }
    }

    #[test]
    fn test_trust_manager_directory_trust() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);
        let now = 1_000_000u64;

        // Create directory and publish B's record
        let mut dir = KeyDirectory::new();
        let mut b_record = AgentRecord::new(
            &b.public_key,
            vec![],
            vec![],
            now,
            now + 86400,
            crate::identity_v1::KEY_ALG_ML_DSA_65,
        );
        b_record.sign(&b.secret_key().unwrap());
        dir.publish(b_record, now).unwrap();

        let tm = TrustManager::new(a_id).with_directory(dir);

        let result = tm.verify_peer(&b_id, &b.public_key, None, now);
        match result {
            TrustResult::Trusted { source, level } => {
                assert_eq!(source, TrustSource::Directory);
                assert_eq!(level, TRUST_LEVEL_FULL);
            }
            _ => panic!("expected Trusted from Directory"),
        }
    }

    #[test]
    fn test_trust_manager_unknown() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id);

        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        match result {
            TrustResult::Unknown { suggestion } => {
                assert_eq!(suggestion, TrustSuggestion::Tofu);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn test_trust_manager_unknown_with_directory_suggests_query() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id).with_directory(KeyDirectory::new());

        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        match result {
            TrustResult::Unknown { suggestion } => {
                assert_eq!(suggestion, TrustSuggestion::QueryDirectory);
            }
            _ => panic!("expected Unknown with QueryDirectory suggestion"),
        }
    }

    #[test]
    fn test_trust_manager_direct_trust_key_mismatch() {
        let a = make_keypair();
        let b = make_keypair();
        let wrong = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id);
        // Cache B's key as the wrong key
        tm.add_direct_trust(b_id, wrong.public_key.clone());

        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        assert!(matches!(result, TrustResult::Untrusted { .. }));
    }

    #[test]
    fn test_policy_strict_rejects_unknown() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id).with_policy(TrustPolicy::Strict);
        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        assert!(!tm.should_accept(&result));
    }

    #[test]
    fn test_policy_permissive_accepts_unknown() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id).with_policy(TrustPolicy::Permissive);
        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        assert!(tm.should_accept(&result));
    }

    #[test]
    fn test_tofu_adds_to_direct_cache() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id);
        assert_eq!(tm.direct_trust_count(), 0);

        tm.accept_tofu(b_id, b.public_key.clone());
        assert_eq!(tm.direct_trust_count(), 1);

        // Now should be directly trusted
        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        assert!(matches!(result, TrustResult::Trusted { .. }));
    }

    #[test]
    fn test_revocation_overrides_direct_trust() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let tm = TrustManager::new(a_id);
        tm.add_direct_trust(b_id, b.public_key.clone());

        // Now revoke B
        let mut crl = crate::revocation::RevocationList::new(1_000_000, 3600);
        crl.revoke(
            b_id,
            1_000_000,
            Some("compromised".into()),
            b_id,
            &b.secret_key().unwrap(),
        );
        tm.revocation_store().lock().unwrap().add_crl(crl);

        // Revocation should override direct trust
        let result = tm.verify_peer(&b_id, &b.public_key, None, 1_000_000);
        assert!(matches!(result, TrustResult::Revoked { .. }));
    }
}
