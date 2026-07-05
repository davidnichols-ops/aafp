//! CA Certificates: optional CA-signed certificates for enterprise deployments
//! (RFC 0011 §5).
//!
//! CA certificates use ML-DSA-65 signatures (NOT X.509) to keep cryptographic
//! primitives consistent with the rest of AAFP and provide post-quantum security.
//!
//! CBOR structure (RFC 0011 §5.2):
//! ```cbor
//! CaCertificate = {
//!     1: tstr,         // type: "aafp-ca-cert-v1"
//!     2: bstr,         // agent_id: 32 bytes
//!     3: bstr,         // public_key: 1952 bytes (ML-DSA-65)
//!     4: tstr,         // issuer: CA name (human-readable)
//!     5: bstr,         // issuer_public_key: 1952 bytes (CA's ML-DSA-65 key)
//!     6: uint,         // serial_number: unique per CA
//!     7: uint,         // not_before: unix timestamp
//!     8: uint,         // not_after: unix timestamp
//!     9: [ *tstr ],    // capabilities: capabilities allowed by this cert
//!     10: bstr,        // ca_signature: ML-DSA-65 over fields 1-9
//!                      //   with domain separator "aafp-v1-ca"
//! }
//! ```

use crate::identity_v1::{AgentId, IdentityError};
use crate::revocation::RevocationStore;
use aafp_cbor::{decode, encode, int_map, int_map_get, CborError, Value};
use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme};
use std::collections::HashSet;
use thiserror::Error;

/// Domain separator for CA certificate signatures (RFC 0011 §5.3).
pub const CA_DOMAIN_SEPARATOR: &[u8] = b"aafp-v1-ca";

/// Type string for CA certificates (RFC 0011 §5.2).
pub const CA_CERT_TYPE_V1: &str = "aafp-ca-cert-v1";

/// CA certificate errors.
#[derive(Debug, Error)]
pub enum CaError {
    /// CBOR encoding/decoding error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    /// Certificate has expired (not_after < now).
    #[error("certificate expired")]
    Expired,
    /// Certificate is not yet valid (not_before > now).
    #[error("certificate not yet valid")]
    NotYetValid,
    /// Missing field in CBOR data.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// Invalid field value.
    #[error("invalid field {field}: {message}")]
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Error message.
        message: String,
    },
    /// Agent ID does not match public key.
    #[error("agent_id does not match public key")]
    AgentIdMismatch,
    /// Invalid public key.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Invalid signature length.
    #[error("invalid signature length")]
    InvalidSignatureLength,
    /// CA is not in the trusted roots set.
    #[error("CA not trusted: {0}")]
    CaNotTrusted(String),
    /// Certificate has been revoked.
    #[error("certificate revoked")]
    Revoked,
    /// Self-signed certificate rejected (issuer == agent) unless CA key is trusted.
    #[error("self-signed certificate rejected")]
    SelfSignedRejected,
    /// Identity error (e.g., invalid AgentId).
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

/// A CA-signed certificate binding an AgentId and public key to capabilities
/// with a validity period (RFC 0011 §5.2).
#[derive(Clone, Debug)]
pub struct CaCertificate {
    /// Type string, always `"aafp-ca-cert-v1"`.
    pub cert_type: String,
    /// 32-byte AgentId of the certified agent.
    pub agent_id: AgentId,
    /// ML-DSA-65 public key of the certified agent (1952 bytes).
    pub public_key: Vec<u8>,
    /// CA name (human-readable).
    pub issuer: String,
    /// CA's ML-DSA-65 public key (1952 bytes).
    pub issuer_public_key: Vec<u8>,
    /// Serial number, unique per CA.
    pub serial_number: u64,
    /// Validity start (unix timestamp).
    pub not_before: u64,
    /// Validity end (unix timestamp).
    pub not_after: u64,
    /// Capabilities allowed by this certificate.
    pub capabilities: Vec<String>,
    /// ML-DSA-65 signature over fields 1-9, signed by the CA.
    pub ca_signature: Vec<u8>,
}

impl CaCertificate {
    /// Issue a CA certificate (RFC 0011 §5.4).
    ///
    /// The CA signs the agent's key with the given validity period and
    /// capabilities. The `ca_secret_key` is used to sign.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        agent_id: AgentId,
        agent_public_key: &[u8],
        issuer_name: &str,
        issuer_public_key: &[u8],
        ca_secret_key: &MlDsa65SecretKey,
        serial_number: u64,
        not_before: u64,
        not_after: u64,
        capabilities: Vec<String>,
    ) -> Self {
        let mut cert = Self {
            cert_type: CA_CERT_TYPE_V1.to_string(),
            agent_id,
            public_key: agent_public_key.to_vec(),
            issuer: issuer_name.to_string(),
            issuer_public_key: issuer_public_key.to_vec(),
            serial_number,
            not_before,
            not_after,
            capabilities,
            ca_signature: Vec::new(),
        };
        let sig_input = cert.signature_input();
        let sig = MlDsa65::sign(ca_secret_key, &sig_input);
        cert.ca_signature = sig.0;
        cert
    }

    /// Compute the signature input (fields 1-9 with domain separator).
    fn signature_input(&self) -> Vec<u8> {
        let cbor = self.to_cbor_without_sig();
        let cbor_bytes = encode(&cbor).unwrap_or_default();
        let mut input = Vec::with_capacity(CA_DOMAIN_SEPARATOR.len() + cbor_bytes.len());
        input.extend_from_slice(CA_DOMAIN_SEPARATOR);
        input.extend_from_slice(&cbor_bytes);
        input
    }

    /// Encode to CBOR without the signature field (for signing).
    fn to_cbor_without_sig(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.cert_type.clone())),
            (2, Value::ByteString(self.agent_id.0.to_vec())),
            (3, Value::ByteString(self.public_key.clone())),
            (4, Value::TextString(self.issuer.clone())),
            (5, Value::ByteString(self.issuer_public_key.clone())),
            (6, Value::Unsigned(self.serial_number)),
            (7, Value::Unsigned(self.not_before)),
            (8, Value::Unsigned(self.not_after)),
            (
                9,
                Value::Array(
                    self.capabilities
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ),
        ])
    }

    /// Encode to CBOR (with signature).
    pub fn to_cbor(&self) -> Value {
        let mut entries = match self.to_cbor_without_sig() {
            Value::IntMap(e) => e,
            _ => Vec::new(),
        };
        entries.push((10, Value::ByteString(self.ca_signature.clone())));
        Value::IntMap(entries)
    }

    /// Decode from a CBOR Value.
    pub fn from_cbor(val: &Value) -> Result<Self, CaError> {
        let get = |k: i64| -> Option<&Value> { int_map_get(val, k) };

        let cert_type = match get(1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(CaError::MissingField("type")),
        };

        let agent_id = match get(2) {
            Some(Value::ByteString(b)) => AgentId::from_bytes(b)?,
            _ => return Err(CaError::MissingField("agent_id")),
        };

        let public_key = match get(3) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => return Err(CaError::MissingField("public_key")),
        };

        let issuer = match get(4) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(CaError::MissingField("issuer")),
        };

        let issuer_public_key = match get(5) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => return Err(CaError::MissingField("issuer_public_key")),
        };

        let serial_number = match get(6) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(CaError::MissingField("serial_number")),
        };

        let not_before = match get(7) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(CaError::MissingField("not_before")),
        };

        let not_after = match get(8) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(CaError::MissingField("not_after")),
        };

        let capabilities = match get(9) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| match v {
                    Value::TextString(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => return Err(CaError::MissingField("capabilities")),
        };

        let ca_signature = match get(10) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => return Err(CaError::MissingField("ca_signature")),
        };

        Ok(Self {
            cert_type,
            agent_id,
            public_key,
            issuer,
            issuer_public_key,
            serial_number,
            not_before,
            not_after,
            capabilities,
            ca_signature,
        })
    }

    /// Encode to CBOR bytes.
    pub fn encode_bytes(&self) -> Result<Vec<u8>, CaError> {
        Ok(encode(&self.to_cbor())?)
    }

    /// Decode from CBOR bytes.
    pub fn decode_bytes(data: &[u8]) -> Result<Self, CaError> {
        let (val, _) = decode(data)?;
        Self::from_cbor(&val)
    }

    /// Verify the certificate's signature and fields (RFC 0011 §5.5).
    ///
    /// Checks:
    /// 1. type == "aafp-ca-cert-v1"
    /// 2. agent_id == SHA-256(public_key)
    /// 3. not_before <= now < not_after
    /// 4. ca_signature verifies using issuer_public_key
    pub fn verify(&self, now: u64) -> Result<(), CaError> {
        // Step 1: Check type
        if self.cert_type != CA_CERT_TYPE_V1 {
            return Err(CaError::InvalidField {
                field: "type",
                message: format!("expected {}, got {}", CA_CERT_TYPE_V1, self.cert_type),
            });
        }

        // Step 2: Check agent_id == SHA-256(public_key)
        let computed_id = AgentId::from_public_key(&self.public_key);
        if self.agent_id != computed_id {
            return Err(CaError::AgentIdMismatch);
        }

        // Step 3: Check validity period
        if now < self.not_before {
            return Err(CaError::NotYetValid);
        }
        if now >= self.not_after {
            return Err(CaError::Expired);
        }

        // Step 4: Verify CA signature
        let sig_input = self.signature_input();
        let ca_pk = MlDsa65PublicKey::from_bytes(&self.issuer_public_key)
            .map_err(|_| CaError::InvalidPublicKey)?;
        let sig = MlDsa65Signature::from_bytes(&self.ca_signature)
            .map_err(|_| CaError::InvalidSignatureLength)?;
        if !MlDsa65::verify(&ca_pk, &sig_input, &sig) {
            return Err(CaError::SignatureVerificationFailed);
        }

        Ok(())
    }

    /// Check if the certificate is expired at the given time.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.not_after
    }

    /// Check if the certificate is self-signed (issuer == agent).
    pub fn is_self_signed(&self) -> bool {
        self.issuer_public_key == self.public_key
    }

    /// Get the CA's AgentId (derived from issuer_public_key).
    pub fn issuer_agent_id(&self) -> AgentId {
        AgentId::from_public_key(&self.issuer_public_key)
    }
}

/// CA certificate verifier: stores trusted root CA keys and verifies
/// certificate chains (RFC 0011 §5.5-5.6).
#[derive(Clone, Debug, Default)]
pub struct CaVerifier {
    /// Trusted root CA public keys.
    trusted_roots: HashSet<Vec<u8>>,
}

impl CaVerifier {
    /// Create a new empty CA verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted root CA public key.
    pub fn add_trusted_root(&mut self, public_key: Vec<u8>) {
        self.trusted_roots.insert(public_key);
    }

    /// Check if a CA public key is in the trusted roots.
    pub fn is_trusted_ca(&self, public_key: &[u8]) -> bool {
        self.trusted_roots.contains(public_key)
    }

    /// Count of trusted roots.
    pub fn trusted_root_count(&self) -> usize {
        self.trusted_roots.len()
    }

    /// Verify a certificate chain (RFC 0011 §5.6).
    ///
    /// For a single certificate (no chain):
    /// 1. Verify the certificate's signature and validity.
    /// 2. Check that the issuer's public key is in the trusted roots.
    /// 3. Check that the certificate is not revoked.
    /// 4. Reject self-signed certificates unless the CA key is trusted.
    ///
    /// For a chain [leaf, intermediate, ..., root]:
    /// 1. Verify each certificate's signature using the next cert's public key.
    /// 2. The root CA's public key must be in the trusted roots.
    pub fn verify_chain(
        &self,
        chain: &[&CaCertificate],
        now: u64,
        revocation_store: Option<&RevocationStore>,
    ) -> Result<(), CaError> {
        if chain.is_empty() {
            return Err(CaError::MissingField("chain"));
        }

        // Verify each link in the chain
        for i in 0..chain.len() {
            let cert = chain[i];

            // Verify the certificate's own signature
            cert.verify(now)?;

            // Check revocation
            if let Some(store) = revocation_store {
                if store.is_revoked(&cert.agent_id) {
                    return Err(CaError::Revoked);
                }
            }

            if i + 1 < chain.len() {
                // This cert should be signed by the next cert's CA
                let next = chain[i + 1];
                if cert.issuer_public_key != next.public_key {
                    return Err(CaError::InvalidField {
                        field: "chain",
                        message: format!(
                            "certificate {} issuer does not match certificate {} public key",
                            i,
                            i + 1
                        ),
                    });
                }
            } else {
                // Last cert in chain: its CA must be a trusted root
                if !self.is_trusted_ca(&cert.issuer_public_key) {
                    return Err(CaError::CaNotTrusted(cert.issuer.clone()));
                }
                // Reject self-signed unless the CA key is explicitly trusted
                if cert.is_self_signed() && !self.is_trusted_ca(&cert.public_key) {
                    return Err(CaError::SelfSignedRejected);
                }
            }
        }

        Ok(())
    }

    /// Verify a single (leaf) certificate against the trusted roots.
    pub fn verify_certificate(
        &self,
        cert: &CaCertificate,
        now: u64,
        revocation_store: Option<&RevocationStore>,
    ) -> Result<(), CaError> {
        self.verify_chain(&[cert], now, revocation_store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::AgentKeypair;

    fn make_keypair() -> AgentKeypair {
        AgentKeypair::generate()
    }

    fn issue_test_cert(
        ca: &AgentKeypair,
        agent: &AgentKeypair,
        now: u64,
        validity_secs: u64,
        capabilities: Vec<&str>,
    ) -> CaCertificate {
        let agent_id = AgentId::from_public_key(&agent.public_key);
        CaCertificate::issue(
            agent_id,
            &agent.public_key,
            "Test CA",
            &ca.public_key,
            &ca.secret_key().unwrap(),
            1,
            now,
            now + validity_secs,
            capabilities.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn test_ca_cert_issue_and_verify() {
        let ca = make_keypair();
        let agent = make_keypair();
        let now = 1_000_000u64;

        let cert = issue_test_cert(&ca, &agent, now, 3600, vec!["inference"]);

        // Verify with valid time
        assert!(cert.verify(now).is_ok());
    }

    #[test]
    fn test_ca_cert_expired() {
        let ca = make_keypair();
        let agent = make_keypair();
        let now = 1_000_000u64;

        let cert = issue_test_cert(&ca, &agent, now, 3600, vec!["inference"]);
        // After expiry
        assert!(matches!(cert.verify(now + 7200), Err(CaError::Expired)));
    }

    #[test]
    fn test_ca_cert_not_yet_valid() {
        let ca = make_keypair();
        let agent = make_keypair();
        let now = 1_000_000u64;

        let cert = issue_test_cert(&ca, &agent, now + 3600, 3600, vec!["inference"]);
        // Before not_before
        assert!(matches!(cert.verify(now), Err(CaError::NotYetValid)));
    }

    #[test]
    fn test_ca_cert_wrong_ca_signature() {
        let ca = make_keypair();
        let wrong_ca = make_keypair();
        let agent = make_keypair();
        let now = 1_000_000u64;

        // Issue with wrong CA key but claim it was signed by `ca`
        let agent_id = AgentId::from_public_key(&agent.public_key);
        let mut cert = CaCertificate::issue(
            agent_id,
            &agent.public_key,
            "Test CA",
            &ca.public_key,                  // Claim this is the issuer
            &wrong_ca.secret_key().unwrap(), // But sign with wrong key
            1,
            now,
            now + 3600,
            vec!["inference".into()],
        );
        // The signature won't match — verify should fail
        let _ = &mut cert;
        assert!(matches!(
            cert.verify(now),
            Err(CaError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_ca_cert_agent_id_mismatch() {
        let ca = make_keypair();
        let agent = make_keypair();
        let now = 1_000_000u64;

        let wrong_id = AgentId([0xFF; 32]);
        let cert = CaCertificate::issue(
            wrong_id,
            &agent.public_key,
            "Test CA",
            &ca.public_key,
            &ca.secret_key().unwrap(),
            1,
            now,
            now + 3600,
            vec!["inference".into()],
        );
        assert!(matches!(cert.verify(now), Err(CaError::AgentIdMismatch)));
    }

    #[test]
    fn test_cbor_roundtrip() {
        let ca = make_keypair();
        let agent = make_keypair();
        let now = 1_000_000u64;

        let cert = issue_test_cert(&ca, &agent, now, 3600, vec!["inference", "translation"]);

        let encoded = cert.encode_bytes().unwrap();
        let decoded = CaCertificate::decode_bytes(&encoded).unwrap();
        assert_eq!(decoded.cert_type, cert.cert_type);
        assert_eq!(decoded.agent_id, cert.agent_id);
        assert_eq!(decoded.public_key, cert.public_key);
        assert_eq!(decoded.issuer, cert.issuer);
        assert_eq!(decoded.issuer_public_key, cert.issuer_public_key);
        assert_eq!(decoded.serial_number, cert.serial_number);
        assert_eq!(decoded.not_before, cert.not_before);
        assert_eq!(decoded.not_after, cert.not_after);
        assert_eq!(decoded.capabilities, cert.capabilities);
        assert_eq!(decoded.ca_signature, cert.ca_signature);
    }

    #[test]
    fn test_ca_verifier_trusted_root() {
        let ca = make_keypair();
        let agent = make_keypair();
        let now = 1_000_000u64;

        let cert = issue_test_cert(&ca, &agent, now, 3600, vec!["inference"]);

        // Without trusting the CA → fail
        let verifier = CaVerifier::new();
        assert!(matches!(
            verifier.verify_certificate(&cert, now, None),
            Err(CaError::CaNotTrusted(_))
        ));

        // With trusted CA → pass
        let mut verifier = CaVerifier::new();
        verifier.add_trusted_root(ca.public_key.clone());
        assert!(verifier.verify_certificate(&cert, now, None).is_ok());
    }

    #[test]
    fn test_ca_verifier_revoked() {
        let ca = make_keypair();
        let agent = make_keypair();
        let now = 1_000_000u64;

        let cert = issue_test_cert(&ca, &agent, now, 3600, vec!["inference"]);

        let mut verifier = CaVerifier::new();
        verifier.add_trusted_root(ca.public_key.clone());

        // Revoke the agent
        let mut store = RevocationStore::new();
        let crl = aafp_cbor::Value::Null; // placeholder
        let _ = crl;
        use crate::revocation::RevocationList;
        let mut crl = RevocationList::new(now, 3600);
        crl.revoke(
            cert.agent_id,
            now,
            Some("compromised".into()),
            cert.agent_id,
            &agent.secret_key().unwrap(),
        );
        store.add_crl(crl);

        assert!(matches!(
            verifier.verify_certificate(&cert, now, Some(&store)),
            Err(CaError::Revoked)
        ));
    }

    #[test]
    fn test_self_signed_rejected_unless_trusted() {
        let agent = make_keypair();
        let now = 1_000_000u64;
        let agent_id = AgentId::from_public_key(&agent.public_key);

        // Self-signed cert (agent signs itself)
        let cert = CaCertificate::issue(
            agent_id,
            &agent.public_key,
            "Self",
            &agent.public_key, // issuer == agent
            &agent.secret_key().unwrap(),
            1,
            now,
            now + 3600,
            vec!["inference".into()],
        );

        assert!(cert.is_self_signed());

        // Without trusting the agent as a CA → reject
        let verifier = CaVerifier::new();
        assert!(matches!(
            verifier.verify_certificate(&cert, now, None),
            Err(CaError::CaNotTrusted(_))
        ));

        // With trusting the agent as a CA → pass
        let mut verifier = CaVerifier::new();
        verifier.add_trusted_root(agent.public_key.clone());
        assert!(verifier.verify_certificate(&cert, now, None).is_ok());
    }

    #[test]
    fn test_certificate_chain() {
        // root CA → intermediate CA → agent
        let root = make_keypair();
        let intermediate = make_keypair();
        let agent = make_keypair();
        let now = 1_000_000u64;

        // Root signs intermediate
        let inter_id = AgentId::from_public_key(&intermediate.public_key);
        let inter_cert = CaCertificate::issue(
            inter_id,
            &intermediate.public_key,
            "Root CA",
            &root.public_key,
            &root.secret_key().unwrap(),
            1,
            now,
            now + 86400,
            vec!["ca".into()],
        );

        // Intermediate signs agent
        let agent_id = AgentId::from_public_key(&agent.public_key);
        let agent_cert = CaCertificate::issue(
            agent_id,
            &agent.public_key,
            "Intermediate CA",
            &intermediate.public_key,
            &intermediate.secret_key().unwrap(),
            1,
            now,
            now + 3600,
            vec!["inference".into()],
        );

        // Verify chain: [agent_cert, inter_cert]
        let mut verifier = CaVerifier::new();
        verifier.add_trusted_root(root.public_key.clone());

        let chain = [&agent_cert, &inter_cert];
        assert!(verifier.verify_chain(&chain, now, None).is_ok());
    }
}
