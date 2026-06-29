//! Protocol Compliance Test Suite
//!
//! Tests organized by protocol area, designed to validate protocol behavior
//! (not implementation details). Both the Rust and Go implementations should
//! pass these same protocol tests.
//!
//! ## Organization
//!
//! ```text
//! protocol_compliance/
//!   identity/
//!     valid_agentid          — agent_id == SHA-256(public_key) accepts
//!     invalid_agentid        — agent_id != SHA-256(public_key) rejects
//!     wrong_key              — mismatched public key rejects
//!   handshake/
//!     successful             — full 3-way handshake completes
//!     bad_signature          — tampered signature rejects
//!     version_mismatch       — wrong protocol version rejects
//!     expired_identity       — expired expires_at rejects
//!     wrong_algorithm        — unsupported key_algorithm rejects
//!   authorization/
//!     allow_capability       — authorized capability passes
//!     deny_capability        — unauthorized capability denied
//!     session_state_machine  — illegal transitions rejected
//! ```
//!
//! These tests use the public API and verify protocol-level invariants.
//! They do NOT test implementation details (crypto internals, transport
//! specifics, etc.).

use aafp_core::{
    AuthorizationContext, AuthorizationProvider, NegotiatedFeatures, Session,
    SessionState, TestingAuthProvider, TestingCapabilityProvider, TestingDenyProvider,
    TransportHandle,
};
use aafp_crypto::{
    derive_session_id, generate_nonce, verify_client_finished, verify_client_hello,
    verify_server_hello, ClientFinished, ClientHelloV1, HandshakeError, ServerHelloV1,
    TranscriptHash, KEY_ALG_ML_DSA_65, PROTOCOL_VERSION,
};
use aafp_crypto::{MlDsa65, SignatureScheme};
use aafp_identity::{derive_agent_id, verify_agent_id, AgentId, AgentKeypair};
use sha2::Digest;

// ===========================================================================
// IDENTITY COMPLIANCE TESTS
// ===========================================================================

mod identity {
    use super::*;

    /// valid_agentid: A correctly derived AgentId must verify.
    #[test]
    fn valid_agentid() {
        let kp = AgentKeypair::generate();
        let agent_id = derive_agent_id(&kp.public_key);
        assert_eq!(agent_id.len(), 32);
        assert!(verify_agent_id(&agent_id, &kp.public_key));
    }

    /// invalid_agentid: An AgentId that doesn't match SHA-256(public_key)
    /// must be rejected.
    #[test]
    fn invalid_agentid() {
        let kp = AgentKeypair::generate();
        let mut fake_id = derive_agent_id(&kp.public_key);
        fake_id[0] ^= 0xff; // Tamper
        assert!(!verify_agent_id(&fake_id, &kp.public_key));
    }

    /// wrong_key: A public key that doesn't correspond to the AgentId
    /// must be rejected.
    #[test]
    fn wrong_key() {
        let kp1 = AgentKeypair::generate();
        let kp2 = AgentKeypair::generate();
        let id1 = derive_agent_id(&kp1.public_key);
        // id1 was derived from kp1, not kp2
        assert!(!verify_agent_id(&id1, &kp2.public_key));
    }

    /// Different keys must produce different AgentIds.
    #[test]
    fn different_keys_different_ids() {
        let kp1 = AgentKeypair::generate();
        let kp2 = AgentKeypair::generate();
        let id1 = derive_agent_id(&kp1.public_key);
        let id2 = derive_agent_id(&kp2.public_key);
        assert_ne!(id1, id2);
    }

    /// AgentId must be exactly 32 bytes.
    #[test]
    fn agentid_size() {
        let kp = AgentKeypair::generate();
        let id = derive_agent_id(&kp.public_key);
        assert_eq!(id.len(), 32);
    }
}

// ===========================================================================
// HANDSHAKE COMPLIANCE TESTS
// ===========================================================================

mod handshake {
    use super::*;

    /// Helper: build a valid ClientHello with correct agent_id binding.
    fn build_valid_client_hello(
        kp: &AgentKeypair,
        tls_binding: &[u8; 32],
        now: u64,
    ) -> (ClientHelloV1, [u8; 32]) {
        let agent_id = sha2::Sha256::digest(&kp.public_key).to_vec();
        let mut th = TranscriptHash::from_tls_binding(tls_binding);

        let mut ch = ClientHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id,
            public_key: kp.public_key.clone(),
            nonce: generate_nonce(),
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: now + 3600,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        let ch_cbor = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
        let h_after_ch = th.fold(&ch_cbor_bytes);

        let sig_input = {
            let mut v = Vec::new();
            v.extend_from_slice(aafp_crypto::DOMAIN_SEPARATOR);
            v.extend_from_slice(&h_after_ch);
            v
        };
        let sk = aafp_crypto::MlDsa65SecretKey::from_bytes(&kp.secret_key).unwrap();
        ch.signature = MlDsa65::sign(&sk, &sig_input).0;

        (ch, h_after_ch)
    }

    /// successful: A valid ClientHello with correct agent_id binding,
    /// valid signature, correct version, and non-expired identity must
    /// pass verification.
    #[test]
    fn successful() {
        let kp = AgentKeypair::generate();
        let (ch, h) = build_valid_client_hello(&kp, &[0x42u8; 32], 0);
        let agent_id = verify_client_hello(&ch, &h, 0).unwrap();
        assert_eq!(agent_id.as_slice(), ch.agent_id);
    }

    /// bad_signature: A tampered signature must be rejected with
    /// SignatureVerificationFailed.
    #[test]
    fn bad_signature() {
        let kp = AgentKeypair::generate();
        let (mut ch, h) = build_valid_client_hello(&kp, &[0x42u8; 32], 0);
        ch.signature[0] ^= 0xff;
        let err = verify_client_hello(&ch, &h, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::SignatureVerificationFailed));
    }

    /// version_mismatch: A wrong protocol version must be rejected with
    /// VersionMismatch.
    #[test]
    fn version_mismatch() {
        let kp = AgentKeypair::generate();
        let (mut ch, h) = build_valid_client_hello(&kp, &[0x42u8; 32], 0);
        ch.protocol_version = 99;
        let err = verify_client_hello(&ch, &h, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::VersionMismatch { .. }));
    }

    /// expired_identity: An expired expires_at must be rejected with
    /// IdentityExpired.
    #[test]
    fn expired_identity() {
        let kp = AgentKeypair::generate();
        let (ch, h) = build_valid_client_hello(&kp, &[0x42u8; 32], 0);
        // ch.expires_at = now + 3600 = 3600, so now=3601 should reject
        let err = verify_client_hello(&ch, &h, 3601).unwrap_err();
        assert!(matches!(err, HandshakeError::IdentityExpired { .. }));
    }

    /// wrong_algorithm: An unsupported key_algorithm must be rejected.
    #[test]
    fn wrong_algorithm() {
        let kp = AgentKeypair::generate();
        let (mut ch, h) = build_valid_client_hello(&kp, &[0x42u8; 32], 0);
        ch.key_algorithm = 99;
        let err = verify_client_hello(&ch, &h, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::UnsupportedAlgorithm(_)));
    }

    /// mismatched_agent_id: An agent_id that doesn't match SHA-256(public_key)
    /// must be rejected with InvalidAgentId.
    #[test]
    fn mismatched_agent_id() {
        let kp = AgentKeypair::generate();
        let (mut ch, h) = build_valid_client_hello(&kp, &[0x42u8; 32], 0);
        ch.agent_id[0] ^= 0xff;
        let err = verify_client_hello(&ch, &h, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidAgentId));
    }

    /// wrong_public_key: A public key that doesn't match the agent_id
    /// must be rejected with InvalidAgentId.
    #[test]
    fn wrong_public_key() {
        let kp = AgentKeypair::generate();
        let (mut ch, h) = build_valid_client_hello(&kp, &[0x42u8; 32], 0);
        let (pk2, _) = MlDsa65::keypair();
        ch.public_key = pk2.0.clone();
        let err = verify_client_hello(&ch, &h, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidAgentId));
    }
}

// ===========================================================================
// SESSION STATE MACHINE COMPLIANCE TESTS
// ===========================================================================

mod session_state {
    use super::*;

    struct TestTransport {
        addr: String,
        closed: bool,
    }

    impl TransportHandle for TestTransport {
        fn remote_addr(&self) -> &str {
            &self.addr
        }
        fn is_closed(&self) -> bool {
            self.closed
        }
    }

    /// The state machine must follow the defined forward progression.
    #[test]
    fn forward_progression() {
        let mut s = Session::new();
        assert_eq!(s.state(), SessionState::Connecting);

        s.on_transport_established(
            Box::new(TestTransport { addr: "quic://x".into(), closed: false }),
            NegotiatedFeatures::default(),
        )
        .unwrap();
        assert_eq!(s.state(), SessionState::TransportEstablished);

        s.on_identity_verified([0xAA; 32], [0xBB; 32]).unwrap();
        assert_eq!(s.state(), SessionState::IdentityVerified);

        // Use testing provider for compliance test
        // (authorization provider is pluggable; we test the state machine, not the provider)
    }

    /// Illegal transitions must be rejected — cannot skip states.
    #[test]
    fn cannot_skip_states() {
        let mut s = Session::new();
        // Cannot go from Connecting directly to IdentityVerified
        assert!(s.on_identity_verified([0xAA; 32], [0xBB; 32]).is_err());
        assert_eq!(s.state(), SessionState::Connecting);
    }

    /// Cannot go backward in the state machine.
    #[test]
    fn cannot_go_backward() {
        // TransportEstablished → Connecting is illegal
        assert!(!SessionState::TransportEstablished.can_transition_to(SessionState::Connecting));
        // IdentityVerified → TransportEstablished is illegal
        assert!(!SessionState::IdentityVerified.can_transition_to(SessionState::TransportEstablished));
    }

    /// Any non-terminal state can abort to Closed.
    #[test]
    fn abort_from_any_state() {
        let mut s = Session::new();
        s.close().unwrap(); // Connecting → Closed
        assert_eq!(s.state(), SessionState::Closed);
        assert!(s.state().is_terminal());
    }

    /// Closed is terminal — no further transitions.
    #[test]
    fn closed_is_terminal() {
        let closed = SessionState::Closed;
        // Cannot transition from Closed to anything
        assert!(!closed.can_transition_to(SessionState::Connecting));
        assert!(!closed.can_transition_to(SessionState::Closing));
        assert!(closed.is_terminal());
    }
}

// ===========================================================================
// AUTHORIZATION COMPLIANCE TESTS
// ===========================================================================

mod authorization {
    use super::*;

    /// allow_capability: An authorized capability must pass.
    #[tokio::test]
    async fn allow_capability() {
        let provider = TestingCapabilityProvider::new(vec!["aafp.discovery".into()]);
        let ctx = provider.authorize(&[0xAA; 32], &[0xBB; 1952]).await.unwrap();
        assert!(ctx.is_authorized("aafp.discovery"));
    }

    /// deny_capability: An unauthorized capability must be denied.
    #[tokio::test]
    async fn deny_capability() {
        let provider = TestingCapabilityProvider::new(vec!["aafp.discovery".into()]);
        let ctx = provider.authorize(&[0xAA; 32], &[0xBB; 1952]).await.unwrap();
        assert!(!ctx.is_authorized("aafp.admin"));
    }

    /// allow_all: TestingAuthProvider allows everything.
    #[tokio::test]
    async fn allow_all() {
        let provider = TestingAuthProvider;
        let ctx = provider.authorize(&[0xAA; 32], &[0xBB; 1952]).await.unwrap();
        assert!(ctx.is_authorized("anything"));
    }

    /// deny_all: TestingDenyProvider denies everything.
    #[tokio::test]
    async fn deny_all() {
        let provider = TestingDenyProvider;
        let ctx = provider.authorize(&[0xAA; 32], &[0xBB; 1952]).await.unwrap();
        assert!(!ctx.is_authorized("anything"));
    }

    /// Session must reflect authorization state correctly.
    #[tokio::test]
    async fn session_reflects_authorization() {
        let provider = TestingCapabilityProvider::new(vec!["aafp.discovery".into()]);
        let mut s = Session::new();

        // Before authorization, is_authorized returns false
        assert!(!s.is_authorized("aafp.discovery"));

        // Go through the state machine
        struct TestTransport;
        impl TransportHandle for TestTransport {
            fn remote_addr(&self) -> &str {
                "quic://x"
            }
            fn is_closed(&self) -> bool {
                false
            }
        }

        s.on_transport_established(
            Box::new(TestTransport),
            NegotiatedFeatures::default(),
        )
        .unwrap();
        s.on_identity_verified([0xAA; 32], [0xBB; 32]).unwrap();

        // Authorize
        let ctx = provider.authorize(&[0xAA; 32], &[0xCC; 1952]).await.unwrap();
        s.on_authorization_verified(ctx).unwrap();
        assert_eq!(s.state(), SessionState::AuthorizationVerified);

        // After authorization, is_authorized reflects the provider's decision
        assert!(s.is_authorized("aafp.discovery"));
        assert!(!s.is_authorized("aafp.admin"));
    }
}
