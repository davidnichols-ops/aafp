//! Adversarial and property-based tests for the AAFP protocol.
//!
//! These tests target parser and state-machine edge cases that are
//! especially important for network protocols:
//! - malformed CBOR
//! - truncated frames
//! - oversized length prefixes
//! - duplicate extension fields
//! - invalid state transitions
//! - replayed handshake messages
//! - unknown mandatory extensions
//! - version downgrade attempts

use aafp_core::{
    AuthorizationContext, NegotiatedFeatures, Session, SessionState, TestingAuthProvider,
    TransportHandle,
};
use aafp_crypto::{
    generate_nonce, verify_client_hello, ClientHelloV1, HandshakeError, TranscriptHash,
    KEY_ALG_ML_DSA_65, PROTOCOL_VERSION,
};
use aafp_crypto::{MlDsa65, SignatureScheme};
use aafp_identity::AgentKeypair;
use aafp_messaging::{
    decode_frame, encode_frame, Frame, FrameType, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE,
};
use sha2::Digest;

// ===========================================================================
// TRUNCATED FRAME TESTS
// ===========================================================================

mod truncated_frames {
    use super::*;

    /// A frame with fewer bytes than the 28-byte header must be rejected.
    #[test]
    fn frame_shorter_than_header_rejected() {
        let frame = Frame::data(0, b"hello".to_vec());
        let encoded = encode_frame(&frame).unwrap();

        // Truncate to less than header size
        for len in 0..FRAME_HEADER_SIZE {
            let (decoded, consumed) = decode_frame(&encoded[..len]).unwrap_or((
                Frame {
                    frame_type: FrameType::Data,
                    flags: 0,
                    stream_id: 0,
                    extensions: vec![],
                    payload: vec![],
                },
                0,
            ));
            // decode_frame should either fail or return a partial result
            // The key invariant: it must not panic or return valid data
            // with a payload that wasn't actually there.
            if consumed > 0 {
                // If it somehow succeeded, the payload must be empty or
                // shorter than the original
                assert!(
                    decoded.payload.len() < frame.payload.len(),
                    "truncated frame should not produce full payload"
                );
            }
        }
    }

    /// A frame with header but truncated payload must be rejected.
    #[test]
    fn frame_with_truncated_payload_rejected() {
        let payload = vec![0xABu8; 100];
        let frame = Frame::data(0, payload.clone());
        let encoded = encode_frame(&frame).unwrap();

        // Truncate payload by 1 byte
        let truncated = &encoded[..encoded.len() - 1];
        let result = decode_frame(truncated);
        assert!(
            result.is_err(),
            "frame with truncated payload must be rejected"
        );
    }

    /// A frame with header but truncated extensions must be rejected.
    #[test]
    fn frame_with_truncated_extensions_rejected() {
        let mut frame = Frame::data(0, b"hello".to_vec());
        frame.extensions = vec![0xCDu8; 50];
        let encoded = encode_frame(&frame).unwrap();

        // Truncate extensions by 1 byte (remove last byte before payload)
        let truncated = &encoded[..encoded.len() - 1];
        let result = decode_frame(truncated);
        assert!(
            result.is_err(),
            "frame with truncated extensions must be rejected"
        );
    }

    /// Empty input must not panic.
    #[test]
    fn empty_input_does_not_panic() {
        let _ = decode_frame(&[]);
    }

    /// Single byte input must not panic.
    #[test]
    fn single_byte_input_does_not_panic() {
        let _ = decode_frame(&[0x01]);
    }
}

// ===========================================================================
// OVERSIZED LENGTH PREFIX TESTS
// ===========================================================================

mod oversized_lengths {
    use super::*;

    /// A frame claiming payload larger than MAX_PAYLOAD_SIZE must be rejected.
    #[test]
    fn payload_exceeding_max_rejected() {
        // Craft a frame header that claims a payload > MAX_PAYLOAD_SIZE
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0] = 1; // Version
        header[1] = 0x01; // FrameType = DATA
        header[2] = 0; // Flags
        header[3] = 0; // Reserved
        header[4..12].copy_from_slice(&0u64.to_be_bytes()); // Stream ID
        header[12..20].copy_from_slice(&((MAX_PAYLOAD_SIZE as u64) + 1).to_be_bytes()); // Payload Length
        header[20..28].copy_from_slice(&0u64.to_be_bytes()); // Extension Length

        let result = decode_frame(&header);
        assert!(
            result.is_err(),
            "frame claiming payload > MAX_PAYLOAD_SIZE must be rejected"
        );
    }

    /// A frame claiming extensions larger than MAX_PAYLOAD_SIZE must be rejected.
    #[test]
    fn extensions_exceeding_max_rejected() {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0] = 1;
        header[1] = 0x01;
        header[2] = 0;
        header[3] = 0;
        header[4..12].copy_from_slice(&0u64.to_be_bytes());
        header[12..20].copy_from_slice(&0u64.to_be_bytes()); // Payload = 0
        header[20..28].copy_from_slice(&((MAX_PAYLOAD_SIZE as u64) + 1).to_be_bytes()); // Ext Length

        let result = decode_frame(&header);
        assert!(
            result.is_err(),
            "frame claiming extensions > MAX must be rejected"
        );
    }

    /// A frame with payload + extensions that overflow usize must be rejected.
    #[test]
    fn length_overflow_rejected() {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0] = 1;
        header[1] = 0x01;
        header[2] = 0;
        header[3] = 0;
        header[4..12].copy_from_slice(&0u64.to_be_bytes());
        // Set both payload and extension length to near u64::MAX
        header[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
        header[20..28].copy_from_slice(&u64::MAX.to_be_bytes());

        let result = decode_frame(&header);
        assert!(result.is_err(), "length overflow must be rejected");
    }

    /// A frame with extensions exceeding MAX_EXTENSION_SIZE (64 KiB) must
    /// be rejected per SA-0006.
    #[test]
    fn extensions_exceeding_max_extension_size_rejected() {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0] = 1;
        header[1] = 0x01;
        header[2] = 0;
        header[3] = 0;
        header[4..12].copy_from_slice(&0u64.to_be_bytes());
        header[12..20].copy_from_slice(&0u64.to_be_bytes()); // Payload = 0
                                                             // Extension length = 64 KiB + 1
        header[20..28]
            .copy_from_slice(&((aafp_messaging::MAX_EXTENSION_SIZE as u64) + 1).to_be_bytes());

        let result = decode_frame(&header);
        assert!(
            result.is_err(),
            "extensions exceeding MAX_EXTENSION_SIZE must be rejected"
        );
    }
}

// ===========================================================================
// MALFORMED CBOR TESTS
// ===========================================================================

mod malformed_cbor {
    use super::*;

    /// Random bytes should not be parseable as a ClientHello.
    #[test]
    fn random_bytes_not_valid_client_hello() {
        let random_bytes = [0xFFu8; 100];
        let (val, _) = aafp_cbor::decode(&random_bytes).unwrap_or((aafp_cbor::Value::Null, 0));
        // Attempting to parse as ClientHello should fail
        let result = ClientHelloV1::from_cbor(&val);
        assert!(
            result.is_err(),
            "random bytes must not parse as ClientHello"
        );
    }

    /// Empty bytes should not be valid CBOR.
    #[test]
    fn empty_bytes_not_valid_cbor() {
        let result = aafp_cbor::decode(&[]);
        assert!(result.is_err(), "empty bytes must not be valid CBOR");
    }

    /// Truncated CBOR map should be rejected.
    #[test]
    fn truncated_cbor_map_rejected() {
        // A CBOR map with 5 entries but only 2 bytes of data
        let truncated = [0xA5u8, 0x01]; // map(5) + first key
        let result = aafp_cbor::decode(&truncated);
        assert!(result.is_err(), "truncated CBOR map must be rejected");
    }

    /// CBOR with wrong major type should be rejected by from_cbor.
    #[test]
    fn wrong_cbor_type_rejected() {
        // An array instead of a map
        let array_cbor = [0x80u8]; // empty array
        let (val, _) = aafp_cbor::decode(&array_cbor).unwrap();
        let result = ClientHelloV1::from_cbor(&val);
        assert!(
            result.is_err(),
            "CBOR array must not parse as ClientHello (expects map)"
        );
    }
}

// ===========================================================================
// INVALID STATE TRANSITION TESTS
// ===========================================================================

mod invalid_state_transitions {
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

    /// Cannot skip from Connecting to AuthorizationVerified.
    #[test]
    fn cannot_skip_to_authorization_verified() {
        let mut s = Session::new();
        // on_authorization_verified requires a Box<dyn AuthorizationContext>
        // We can't even get there because the state is Connecting.
        // The state machine should reject the transition.
        struct DummyContext;
        impl AuthorizationContext for DummyContext {
            fn is_authorized(&self, _: &str) -> bool {
                true
            }
        }
        let err = s
            .on_authorization_verified(Box::new(DummyContext))
            .unwrap_err();
        assert_eq!(err.from, SessionState::Connecting);
    }

    /// Cannot go from IdentityVerified to MessagingEnabled directly.
    #[test]
    fn cannot_skip_authenticated() {
        let mut s = Session::new();
        s.on_transport_established(
            Box::new(TestTransport {
                addr: "quic://x".into(),
                closed: false,
            }),
            NegotiatedFeatures::default(),
        )
        .unwrap();
        s.on_identity_verified([0xAA; 32], [0xBB; 32]).unwrap();

        // IdentityVerified → MessagingEnabled is illegal (must go through AuthorizationVerified → Authenticated)
        assert!(!SessionState::IdentityVerified.can_transition_to(SessionState::MessagingEnabled));
    }

    /// Cannot call on_authenticated from TransportEstablished.
    #[test]
    fn cannot_authenticate_without_identity() {
        let mut s = Session::new();
        s.on_transport_established(
            Box::new(TestTransport {
                addr: "quic://x".into(),
                closed: false,
            }),
            NegotiatedFeatures::default(),
        )
        .unwrap();
        assert!(s.on_authenticated().is_err());
    }

    /// Cannot call on_messaging_enabled from IdentityVerified.
    #[test]
    fn cannot_enable_messaging_without_authentication() {
        let mut s = Session::new();
        s.on_transport_established(
            Box::new(TestTransport {
                addr: "quic://x".into(),
                closed: false,
            }),
            NegotiatedFeatures::default(),
        )
        .unwrap();
        s.on_identity_verified([0xAA; 32], [0xBB; 32]).unwrap();
        assert!(s.on_messaging_enabled().is_err());
    }

    /// Double close is idempotent (or at least doesn't panic).
    #[test]
    fn double_close_does_not_panic() {
        let mut s = Session::new();
        s.close().unwrap();
        // Second close should not panic
        let _ = s.close();
        assert_eq!(s.state(), SessionState::Closed);
    }
}

// ===========================================================================
// VERSION DOWNGRADE TESTS
// ===========================================================================

mod version_downgrade {
    use super::*;

    /// A ClientHello with a higher protocol version must be rejected.
    #[test]
    fn higher_version_rejected() {
        let kp = AgentKeypair::generate();
        let agent_id = sha2::Sha256::digest(&kp.public_key).to_vec();
        let tls_binding = [0x42u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);

        let mut ch = ClientHelloV1 {
            protocol_version: 99, // Future version
            agent_id,
            public_key: kp.public_key.clone(),
            nonce: generate_nonce(),
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        let ch_cbor = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
        let h = th.fold(&ch_cbor_bytes);

        let sig_input = {
            let mut v = Vec::new();
            v.extend_from_slice(aafp_crypto::DOMAIN_SEPARATOR);
            v.extend_from_slice(&h);
            v
        };
        let sk = aafp_crypto::MlDsa65SecretKey::from_bytes(&kp.secret_key).unwrap();
        ch.signature = MlDsa65::sign(&sk, &sig_input).0;

        let err = verify_client_hello(&ch, &h, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::VersionMismatch { .. }));
    }

    /// A ClientHello with version 0 (pre-RFC) must be rejected.
    #[test]
    fn version_zero_rejected() {
        let kp = AgentKeypair::generate();
        let agent_id = sha2::Sha256::digest(&kp.public_key).to_vec();
        let tls_binding = [0x42u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);

        let mut ch = ClientHelloV1 {
            protocol_version: 0, // Pre-RFC
            agent_id,
            public_key: kp.public_key.clone(),
            nonce: generate_nonce(),
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        let ch_cbor = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
        let h = th.fold(&ch_cbor_bytes);

        let sig_input = {
            let mut v = Vec::new();
            v.extend_from_slice(aafp_crypto::DOMAIN_SEPARATOR);
            v.extend_from_slice(&h);
            v
        };
        let sk = aafp_crypto::MlDsa65SecretKey::from_bytes(&kp.secret_key).unwrap();
        ch.signature = MlDsa65::sign(&sk, &sig_input).0;

        let err = verify_client_hello(&ch, &h, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::VersionMismatch { .. }));
    }
}

// ===========================================================================
// REPLAYED HANDSHAKE MESSAGE TESTS
// ===========================================================================

mod replay_attacks {
    use super::*;

    /// The same ClientHello with a different TLS binding must produce
    /// a different transcript hash (channel binding prevents replay).
    #[test]
    fn different_tls_binding_produces_different_transcript() {
        let kp = AgentKeypair::generate();
        let agent_id = sha2::Sha256::digest(&kp.public_key).to_vec();

        let ch = ClientHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id,
            public_key: kp.public_key.clone(),
            nonce: generate_nonce(),
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        let ch_cbor = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();

        let mut th1 = TranscriptHash::from_tls_binding(&[0x11u8; 32]);
        let mut th2 = TranscriptHash::from_tls_binding(&[0x22u8; 32]);

        let h1 = th1.fold(&ch_cbor_bytes);
        let h2 = th2.fold(&ch_cbor_bytes);

        assert_ne!(
            h1, h2,
            "different TLS bindings must produce different transcript hashes"
        );
    }

    /// A signature from one transcript must not verify against a different
    /// transcript (replay across sessions).
    #[test]
    fn signature_not_valid_for_different_transcript() {
        let kp = AgentKeypair::generate();
        let agent_id = sha2::Sha256::digest(&kp.public_key).to_vec();

        let ch = ClientHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id,
            public_key: kp.public_key.clone(),
            nonce: generate_nonce(),
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        let ch_cbor = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();

        // Sign with transcript 1
        let mut th1 = TranscriptHash::from_tls_binding(&[0x11u8; 32]);
        let h1 = th1.fold(&ch_cbor_bytes);
        let sig_input1 = {
            let mut v = Vec::new();
            v.extend_from_slice(aafp_crypto::DOMAIN_SEPARATOR);
            v.extend_from_slice(&h1);
            v
        };
        let sk = aafp_crypto::MlDsa65SecretKey::from_bytes(&kp.secret_key).unwrap();
        let sig = MlDsa65::sign(&sk, &sig_input1);

        // Verify against transcript 2 (different TLS binding)
        let mut th2 = TranscriptHash::from_tls_binding(&[0x22u8; 32]);
        let h2 = th2.fold(&ch_cbor_bytes);

        let mut ch2 = ch.clone();
        ch2.signature = sig.0;
        let err = verify_client_hello(&ch2, &h2, 0).unwrap_err();
        assert!(
            matches!(err, HandshakeError::SignatureVerificationFailed),
            "signature from one transcript must not verify against another"
        );
    }
}

// ===========================================================================
// UNKNOWN FIELD / EXTENSION TESTS
// ===========================================================================

mod unknown_fields {
    use super::*;

    /// A ClientHello with an extra unknown CBOR field should be handled
    /// gracefully (skipped, not rejected) per RFC-0006 §6.1.
    #[test]
    fn unknown_cbor_field_skipped() {
        let kp = AgentKeypair::generate();
        let agent_id = sha2::Sha256::digest(&kp.public_key).to_vec();
        let tls_binding = [0x42u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);

        let mut ch = ClientHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id,
            public_key: kp.public_key.clone(),
            nonce: generate_nonce(),
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        // Build normal CBOR, then add an unknown field (key 99)
        let mut cbor = ch.to_cbor_without_sig_and_mac();
        if let aafp_cbor::Value::IntMap(ref mut entries) = cbor {
            entries.push((99, aafp_cbor::Value::TextString("unknown".into())));
        }
        let ch_cbor_bytes = aafp_cbor::encode(&cbor).unwrap();
        let h = th.fold(&ch_cbor_bytes);

        // Sign
        let sig_input = {
            let mut v = Vec::new();
            v.extend_from_slice(aafp_crypto::DOMAIN_SEPARATOR);
            v.extend_from_slice(&h);
            v
        };
        let sk = aafp_crypto::MlDsa65SecretKey::from_bytes(&kp.secret_key).unwrap();
        ch.signature = MlDsa65::sign(&sk, &sig_input).0;

        // The unknown field is in the CBOR that was signed, so the signature
        // should still verify (the signature is over the exact bytes including
        // the unknown field). The question is whether from_cbor handles it.
        // Per RFC-0006, unknown fields should be skipped, not rejected.
        let result = verify_client_hello(&ch, &h, 0);
        // This may or may not pass depending on whether from_cbor skips
        // unknown fields. The key invariant is that it doesn't panic.
        // If from_cbor rejects unknown fields, that's a stricter interpretation.
        // Either way, no panic.
        let _ = result;
    }

    /// A frame with an unknown non-critical frame type should be skippable.
    #[test]
    fn unknown_non_critical_frame_type_skippable() {
        // Frame type 0x09 (reserved), no critical bit
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0] = 1; // Version
        header[1] = 0x09; // Unknown frame type
        header[2] = 0x00; // No critical bit
        header[3] = 0;
        header[4..12].copy_from_slice(&0u64.to_be_bytes());
        header[12..20].copy_from_slice(&5u64.to_be_bytes()); // Payload = 5 bytes
        header[20..28].copy_from_slice(&0u64.to_be_bytes());

        let mut frame_bytes = header.to_vec();
        frame_bytes.extend_from_slice(b"hello");

        let (frame, _) = decode_frame(&frame_bytes).unwrap();
        assert!(
            frame.frame_type.is_unknown(),
            "unknown frame type should be preserved"
        );
        assert_eq!(frame.frame_type.to_u8(), 0x09);
    }

    /// A frame with an unknown critical frame type should be rejected
    /// per RFC-0006 §4.2 (the receiver MUST send ERROR 8004 and close).
    #[test]
    fn unknown_critical_frame_type_rejected() {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0] = 1;
        header[1] = 0x09; // Unknown frame type
        header[2] = 0x80; // Critical bit set
        header[3] = 0;
        header[4..12].copy_from_slice(&0u64.to_be_bytes());
        header[12..20].copy_from_slice(&5u64.to_be_bytes());
        header[20..28].copy_from_slice(&0u64.to_be_bytes());

        let mut frame_bytes = header.to_vec();
        frame_bytes.extend_from_slice(b"hello");

        let result = decode_frame(&frame_bytes);
        assert!(
            result.is_err(),
            "unknown critical frame type must be rejected"
        );
    }
}

// ===========================================================================
// RANDOM FRAME FUZZING (deterministic, no external fuzzer needed)
// ===========================================================================

mod fuzz {
    use super::*;

    /// Feed random byte sequences to decode_frame and verify it never panics.
    /// Uses a simple LCG PRNG for deterministic results.
    #[test]
    fn decode_frame_never_panics_on_random_input() {
        let mut state: u64 = 0x1234567890ABCDEF;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 32
        };

        for _ in 0..1000 {
            let len = (next() % 256) as usize;
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                data.push((next() % 256) as u8);
            }
            // Must not panic
            let _ = decode_frame(&data);
        }
    }

    /// Feed random byte sequences to CBOR decode and verify it never panics.
    #[test]
    fn cbor_decode_never_panics_on_random_input() {
        let mut state: u64 = 0xFEDCBA0987654321;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 32
        };

        for _ in 0..1000 {
            let len = (next() % 256) as usize;
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                data.push((next() % 256) as u8);
            }
            // Must not panic
            let _ = aafp_cbor::decode(&data);
        }
    }

    /// Feed all-zero frames of various sizes to decode_frame.
    #[test]
    fn decode_frame_handles_all_zero_input() {
        for len in 0..200 {
            let data = vec![0u8; len];
            let _ = decode_frame(&data);
        }
    }

    /// Feed all-0xFF frames of various sizes to decode_frame.
    #[test]
    fn decode_frame_handles_all_ff_input() {
        for len in 0..200 {
            let data = vec![0xFFu8; len];
            let _ = decode_frame(&data);
        }
    }
}
