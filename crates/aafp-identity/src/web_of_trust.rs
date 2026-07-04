//! Web of Trust: peer-to-peer key signing for decentralized trust (RFC 0011 §4).
//!
//! Implements:
//! - `TrustSignature`: signed statement that one agent trusts another's key
//! - `WebOfTrust`: stores trust signatures and computes transitive trust levels
//!
//! Trust levels (RFC 0011 §2):
//! - 0 = None
//! - 1 = Marginal (transitive trust decays to this after one hop)
//! - 2 = Full (direct WoT signature or CA certificate)
//! - 3 = Ultimate (only the agent's own key; never granted transitively)
//!
//! Transitive trust decay (RFC 0011 §2.1):
//! - Direct signature: trust_level as signed (max Full = 2)
//! - One hop: Marginal (1)
//! - Two+ hops: None (0)

use crate::identity_v1::{AgentId, IdentityError};
use aafp_cbor::{decode, encode, int_map, int_map_get, CborError, Value};
use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme};
use std::collections::HashMap;
use thiserror::Error;

/// Domain separator for WoT signatures (RFC 0011 §4.3).
pub const WOT_DOMAIN_SEPARATOR: &[u8] = b"aafp-v1-wot";

/// Type string for TrustSignature (RFC 0011 §4.2).
pub const WOT_SIG_TYPE_V1: &str = "aafp-wot-sig-v1";

/// Trust level: None (0).
pub const TRUST_LEVEL_NONE: u8 = 0;
/// Trust level: Marginal (1).
pub const TRUST_LEVEL_MARGINAL: u8 = 1;
/// Trust level: Full (2).
pub const TRUST_LEVEL_FULL: u8 = 2;
/// Trust level: Ultimate (3) — only for self.
pub const TRUST_LEVEL_ULTIMATE: u8 = 3;

/// Recommended WoT signature validity: 90 days (RFC 0011 §4.4).
pub const RECOMMENDED_WOT_VALIDITY_SECS: u64 = 90 * 24 * 60 * 60;

/// WoT errors.
#[derive(Debug, Error)]
pub enum WotError {
    /// CBOR encoding/decoding error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    /// Trust signature has expired.
    #[error("trust signature expired")]
    Expired,
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
    /// Invalid trust level (must be 0-3).
    #[error("invalid trust level: {0}")]
    InvalidTrustLevel(u8),
    /// Agent ID does not match public key.
    #[error("agent_id does not match public key")]
    AgentIdMismatch,
    /// Invalid public key.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Invalid signature length.
    #[error("invalid signature length")]
    InvalidSignatureLength,
    /// Identity error (e.g., invalid AgentId).
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

/// A signed trust assertion: agent `signer` trusts agent `signed`'s key
/// at a given `trust_level` until `expiry` (RFC 0011 §4.2).
///
/// CBOR structure (integer keys):
/// ```cbor
/// TrustSignature = {
///     1: tstr,    // type: "aafp-wot-sig-v1"
///     2: bstr,    // signer_agent_id: 32 bytes
///     3: bstr,    // signed_agent_id: 32 bytes
///     4: bstr,    // signed_public_key: 1952 bytes (ML-DSA-65)
///     5: uint,    // trust_level: 0-3
///     6: uint,    // expiry: unix timestamp
///     7: bstr,    // signature: ML-DSA-65 over fields 1-6
///                  //   with domain separator "aafp-v1-wot"
/// }
/// ```
#[derive(Clone, Debug)]
pub struct TrustSignature {
    /// Type string, always `"aafp-wot-sig-v1"`.
    pub sig_type: String,
    /// 32-byte AgentId of the signer.
    pub signer_agent_id: AgentId,
    /// 32-byte AgentId of the signed agent.
    pub signed_agent_id: AgentId,
    /// ML-DSA-65 public key of the signed agent (1952 bytes).
    pub signed_public_key: Vec<u8>,
    /// Trust level (0-3).
    pub trust_level: u8,
    /// Expiry timestamp (unix seconds).
    pub expiry: u64,
    /// ML-DSA-65 signature over fields 1-6.
    pub signature: Vec<u8>,
}

impl TrustSignature {
    /// Create and sign a trust signature.
    ///
    /// Agent `signer` signs `signed`'s key at `trust_level` until `expiry`.
    /// The `signer_secret_key` is used to sign. The `signer_agent_id` must
    /// be the AgentId derived from the signer's public key.
    pub fn new(
        signer_agent_id: AgentId,
        signed_agent_id: AgentId,
        signed_public_key: &[u8],
        trust_level: u8,
        expiry: u64,
        signer_secret_key: &MlDsa65SecretKey,
    ) -> Result<Self, WotError> {
        if trust_level > TRUST_LEVEL_ULTIMATE {
            return Err(WotError::InvalidTrustLevel(trust_level));
        }
        let mut sig = Self {
            sig_type: WOT_SIG_TYPE_V1.to_string(),
            signer_agent_id,
            signed_agent_id,
            signed_public_key: signed_public_key.to_vec(),
            trust_level,
            expiry,
            signature: Vec::new(),
        };
        let sig_input = sig.signature_input();
        let ml_sig = MlDsa65::sign(signer_secret_key, &sig_input);
        sig.signature = ml_sig.0;
        Ok(sig)
    }

    /// Compute the signature input (fields 1-6 with domain separator).
    fn signature_input(&self) -> Vec<u8> {
        let cbor = self.to_cbor_without_sig();
        let cbor_bytes = encode(&cbor).unwrap_or_default();
        let mut input = Vec::with_capacity(WOT_DOMAIN_SEPARATOR.len() + cbor_bytes.len());
        input.extend_from_slice(WOT_DOMAIN_SEPARATOR);
        input.extend_from_slice(&cbor_bytes);
        input
    }

    /// Encode to CBOR without the signature field (for signing).
    fn to_cbor_without_sig(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.sig_type.clone())),
            (2, Value::ByteString(self.signer_agent_id.0.to_vec())),
            (3, Value::ByteString(self.signed_agent_id.0.to_vec())),
            (4, Value::ByteString(self.signed_public_key.clone())),
            (5, Value::Unsigned(self.trust_level as u64)),
            (6, Value::Unsigned(self.expiry)),
        ])
    }

    /// Encode to CBOR (with signature).
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.sig_type.clone())),
            (2, Value::ByteString(self.signer_agent_id.0.to_vec())),
            (3, Value::ByteString(self.signed_agent_id.0.to_vec())),
            (4, Value::ByteString(self.signed_public_key.clone())),
            (5, Value::Unsigned(self.trust_level as u64)),
            (6, Value::Unsigned(self.expiry)),
            (7, Value::ByteString(self.signature.clone())),
        ])
    }

    /// Decode from a CBOR Value.
    pub fn from_cbor(val: &Value) -> Result<Self, WotError> {
        let get = |k: i64| -> Option<&Value> { int_map_get(val, k) };

        let sig_type = match get(1) {
            Some(Value::TextString(s)) => s.clone(),
            Some(other) => {
                return Err(WotError::InvalidField {
                    field: "type",
                    message: format!("expected tstr, got {:?}", other),
                })
            }
            None => return Err(WotError::MissingField("type")),
        };

        let signer_agent_id = match get(2) {
            Some(Value::ByteString(b)) => AgentId::from_bytes(b)?,
            Some(other) => {
                return Err(WotError::InvalidField {
                    field: "signer_agent_id",
                    message: format!("expected bstr, got {:?}", other),
                })
            }
            None => return Err(WotError::MissingField("signer_agent_id")),
        };

        let signed_agent_id = match get(3) {
            Some(Value::ByteString(b)) => AgentId::from_bytes(b)?,
            Some(other) => {
                return Err(WotError::InvalidField {
                    field: "signed_agent_id",
                    message: format!("expected bstr, got {:?}", other),
                })
            }
            None => return Err(WotError::MissingField("signed_agent_id")),
        };

        let signed_public_key = match get(4) {
            Some(Value::ByteString(b)) => b.clone(),
            Some(other) => {
                return Err(WotError::InvalidField {
                    field: "signed_public_key",
                    message: format!("expected bstr, got {:?}", other),
                })
            }
            None => return Err(WotError::MissingField("signed_public_key")),
        };

        let trust_level = match get(5) {
            Some(Value::Unsigned(n)) => *n as u8,
            Some(other) => {
                return Err(WotError::InvalidField {
                    field: "trust_level",
                    message: format!("expected uint, got {:?}", other),
                })
            }
            None => return Err(WotError::MissingField("trust_level")),
        };

        let expiry = match get(6) {
            Some(Value::Unsigned(n)) => *n,
            Some(other) => {
                return Err(WotError::InvalidField {
                    field: "expiry",
                    message: format!("expected uint, got {:?}", other),
                })
            }
            None => return Err(WotError::MissingField("expiry")),
        };

        let signature = match get(7) {
            Some(Value::ByteString(b)) => b.clone(),
            Some(other) => {
                return Err(WotError::InvalidField {
                    field: "signature",
                    message: format!("expected bstr, got {:?}", other),
                })
            }
            None => return Err(WotError::MissingField("signature")),
        };

        Ok(Self {
            sig_type,
            signer_agent_id,
            signed_agent_id,
            signed_public_key,
            trust_level,
            expiry,
            signature,
        })
    }

    /// Encode to CBOR bytes.
    pub fn encode(&self) -> Result<Vec<u8>, WotError> {
        Ok(encode(&self.to_cbor())?)
    }

    /// Decode from CBOR bytes.
    pub fn decode(data: &[u8]) -> Result<Self, WotError> {
        let (val, _) = decode(data)?;
        Self::from_cbor(&val)
    }

    /// Verify the trust signature (RFC 0011 §4.5).
    ///
    /// Checks:
    /// 1. type == "aafp-wot-sig-v1"
    /// 2. signed_agent_id == SHA-256(signed_public_key)
    /// 3. trust_level is in range [0, 3]
    /// 4. Signature verifies using signer's public key
    /// 5. expiry > now (if `now` is provided)
    pub fn verify(
        &self,
        signer_public_key: &MlDsa65PublicKey,
        now: Option<u64>,
    ) -> Result<(), WotError> {
        // Step 1: Check type
        if self.sig_type != WOT_SIG_TYPE_V1 {
            return Err(WotError::InvalidField {
                field: "type",
                message: format!("expected {}, got {}", WOT_SIG_TYPE_V1, self.sig_type),
            });
        }

        // Step 2: Check signed_agent_id == SHA-256(signed_public_key)
        let computed_id = AgentId::from_public_key(&self.signed_public_key);
        if self.signed_agent_id != computed_id {
            return Err(WotError::AgentIdMismatch);
        }

        // Step 3: Check trust_level range
        if self.trust_level > TRUST_LEVEL_ULTIMATE {
            return Err(WotError::InvalidTrustLevel(self.trust_level));
        }

        // Step 4: Verify signature
        let sig_input = self.signature_input();
        let sig = MlDsa65Signature::from_bytes(&self.signature)
            .map_err(|_| WotError::InvalidSignatureLength)?;
        if !MlDsa65::verify(signer_public_key, &sig_input, &sig) {
            return Err(WotError::SignatureVerificationFailed);
        }

        // Step 5: Check expiry
        if let Some(now) = now {
            if self.expiry <= now {
                return Err(WotError::Expired);
            }
        }

        Ok(())
    }

    /// Check if the signature is expired at the given time.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expiry <= now
    }
}

/// Web of Trust: stores trust signatures and computes transitive trust
/// levels (RFC 0011 §4.6).
///
/// Trust computation uses BFS from the agent's own AgentId through the
/// trust graph:
/// - Direct signatures: trust_level as signed (max 2)
/// - One hop: Marginal (1)
/// - Two+ hops: None (0)
/// - Ultimate (3) is never granted transitively
#[derive(Clone, Debug, Default)]
pub struct WebOfTrust {
    /// The agent's own AgentId (trust root).
    own_agent_id: Option<AgentId>,
    /// All known trust signatures, keyed by signer → signed.
    signatures: HashMap<AgentId, Vec<TrustSignature>>,
    /// Known public keys for signers (needed for verification).
    /// Maps AgentId → public key bytes.
    known_public_keys: HashMap<AgentId, Vec<u8>>,
}

impl WebOfTrust {
    /// Create a new empty Web of Trust.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the agent's own AgentId (the trust root).
    pub fn set_own_agent_id(&mut self, agent_id: AgentId) {
        self.own_agent_id = Some(agent_id);
    }

    /// Get the agent's own AgentId.
    pub fn own_agent_id(&self) -> Option<&AgentId> {
        self.own_agent_id.as_ref()
    }

    /// Add a known public key for an agent (needed for signature verification).
    pub fn add_known_public_key(&mut self, agent_id: AgentId, public_key: Vec<u8>) {
        self.known_public_keys.insert(agent_id, public_key);
    }

    /// Add a trust signature to the WoT (RFC 0011 §4.8).
    ///
    /// The signature is stored and used in trust computation. The signer's
    /// public key should be added via `add_known_public_key` for verification.
    pub fn add_trust_signature(&mut self, sig: TrustSignature) {
        let signer = sig.signer_agent_id;
        let signed_id = sig.signed_agent_id;
        let signed_pk = sig.signed_public_key.clone();
        // Also record the signed public key
        self.known_public_keys.insert(signed_id, signed_pk);
        self.signatures.entry(signer).or_default().push(sig);
    }

    /// Get all trust signatures signed by the given agent.
    pub fn signatures_by(&self, signer: &AgentId) -> &[TrustSignature] {
        self.signatures
            .get(signer)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all trust signatures in the WoT.
    pub fn all_signatures(&self) -> Vec<&TrustSignature> {
        self.signatures.values().flat_map(|v| v.iter()).collect()
    }

    /// Count of trust signatures.
    pub fn signature_count(&self) -> usize {
        self.signatures.values().map(|v| v.len()).sum()
    }

    /// Compute the trust level for a target agent (RFC 0011 §4.6).
    ///
    /// Uses BFS from the agent's own AgentId:
    /// - Direct signature: trust_level as signed (max Full = 2)
    /// - One hop: Marginal (1)
    /// - Two+ hops: None (0)
    /// - Ultimate (3) only for own key
    ///
    /// Expired signatures are ignored. Returns 0 if no trust path exists.
    pub fn trust_level(&self, target: &AgentId, now: u64) -> u8 {
        let own = match &self.own_agent_id {
            Some(id) => id,
            None => return TRUST_LEVEL_NONE,
        };

        // Ultimate trust for own key
        if own == target {
            return TRUST_LEVEL_ULTIMATE;
        }

        // Level 0: direct signatures from own_agent_id
        let mut best = TRUST_LEVEL_NONE;
        if let Some(direct_sigs) = self.signatures.get(own) {
            for sig in direct_sigs {
                if sig.is_expired(now) {
                    continue;
                }
                if &sig.signed_agent_id == target {
                    // Direct: trust_level as signed, capped at Full (2)
                    let level = sig.trust_level.min(TRUST_LEVEL_FULL);
                    if level > best {
                        best = level;
                    }
                }
            }
        }
        if best >= TRUST_LEVEL_MARGINAL {
            return best;
        }

        // Level 1: one-hop transitive trust (Marginal)
        // Find agents that own_agent_id directly trusts (Full or Marginal),
        // then check if they directly trust the target.
        if let Some(direct_sigs) = self.signatures.get(own) {
            for sig in direct_sigs {
                if sig.is_expired(now) {
                    continue;
                }
                if sig.trust_level < TRUST_LEVEL_MARGINAL {
                    continue;
                }
                // sig.signed_agent_id is an intermediary we trust
                let intermediary = &sig.signed_agent_id;
                if intermediary == target {
                    continue; // Already checked above
                }
                // Check if intermediary trusts target
                if let Some(inter_sigs) = self.signatures.get(intermediary) {
                    for inter_sig in inter_sigs {
                        if inter_sig.is_expired(now) {
                            continue;
                        }
                        if &inter_sig.signed_agent_id == target {
                            // One hop: Marginal (1)
                            if TRUST_LEVEL_MARGINAL > best {
                                best = TRUST_LEVEL_MARGINAL;
                            }
                        }
                    }
                }
            }
        }

        // Two+ hops: None (0) — no further BFS needed per RFC 0011 §2.1
        best
    }

    /// Check if a target is trusted at or above the given level.
    pub fn is_trusted(&self, target: &AgentId, min_level: u8, now: u64) -> bool {
        self.trust_level(target, now) >= min_level
    }

    /// Export the WoT to CBOR for persistence.
    pub fn export_trust(&self) -> Result<Vec<u8>, WotError> {
        let sigs: Vec<Value> = self
            .signatures
            .values()
            .flat_map(|v| v.iter())
            .map(|s| s.to_cbor())
            .collect();
        let own = self
            .own_agent_id
            .as_ref()
            .map(|id| Value::ByteString(id.0.to_vec()))
            .unwrap_or(Value::Null);
        let val = int_map(vec![(1, Value::Array(sigs)), (2, own)]);
        Ok(encode(&val)?)
    }

    /// Import trust signatures from CBOR (merges into existing WoT).
    pub fn import_trust(&mut self, data: &[u8]) -> Result<(), WotError> {
        let (val, _) = decode(data)?;
        let get = |k: i64| -> Option<&Value> { int_map_get(&val, k) };

        if let Some(Value::Array(sigs)) = get(1) {
            for sig_val in sigs {
                let sig = TrustSignature::from_cbor(sig_val)?;
                self.add_trust_signature(sig);
            }
        }

        if let Some(Value::ByteString(b)) = get(2) {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                self.own_agent_id = Some(AgentId(arr));
            }
        }

        Ok(())
    }

    /// Remove expired trust signatures.
    pub fn evict_expired(&mut self, now: u64) -> usize {
        let mut removed = 0;
        for sigs in self.signatures.values_mut() {
            let before = sigs.len();
            sigs.retain(|s| !s.is_expired(now));
            removed += before - sigs.len();
        }
        // Remove empty entries
        self.signatures.retain(|_, v| !v.is_empty());
        removed
    }

    /// Get all agents that the given signer directly trusts.
    pub fn trusted_by(&self, signer: &AgentId, now: u64) -> Vec<(&AgentId, u8)> {
        self.signatures
            .get(signer)
            .map(|sigs| {
                sigs.iter()
                    .filter(|s| !s.is_expired(now))
                    .map(|s| (&s.signed_agent_id, s.trust_level))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::AgentKeypair;

    fn make_keypair() -> AgentKeypair {
        AgentKeypair::generate()
    }

    #[test]
    fn test_trust_signature_sign_and_verify() {
        let signer = make_keypair();
        let signed = make_keypair();
        let signer_id = AgentId::from_public_key(&signer.public_key);
        let signed_id = AgentId::from_public_key(&signed.public_key);
        let signer_sk = signer.secret_key().unwrap();
        let signer_pk = signer.public_key().unwrap();

        let now = 1_000_000u64;
        let expiry = now + RECOMMENDED_WOT_VALIDITY_SECS;

        let sig = TrustSignature::new(
            signer_id,
            signed_id,
            &signed.public_key,
            TRUST_LEVEL_FULL,
            expiry,
            &signer_sk,
        )
        .unwrap();

        // Verify with correct signer public key
        assert!(sig.verify(&signer_pk, Some(now)).is_ok());

        // Verify with wrong signer public key
        let wrong = make_keypair();
        let wrong_pk = wrong.public_key().unwrap();
        assert!(matches!(
            sig.verify(&wrong_pk, Some(now)),
            Err(WotError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_trust_signature_expired() {
        let signer = make_keypair();
        let signed = make_keypair();
        let signer_id = AgentId::from_public_key(&signer.public_key);
        let signed_id = AgentId::from_public_key(&signed.public_key);

        let now = 1_000_000u64;
        let expiry = now - 1; // Already expired

        let sig = TrustSignature::new(
            signer_id,
            signed_id,
            &signed.public_key,
            TRUST_LEVEL_FULL,
            expiry,
            &signer.secret_key().unwrap(),
        )
        .unwrap();

        let signer_pk = signer.public_key().unwrap();
        assert!(matches!(
            sig.verify(&signer_pk, Some(now)),
            Err(WotError::Expired)
        ));
        assert!(sig.is_expired(now));
    }

    #[test]
    fn test_trust_signature_agent_id_mismatch() {
        let signer = make_keypair();
        let signed = make_keypair();
        let signer_id = AgentId::from_public_key(&signer.public_key);
        let wrong_signed_id = AgentId([0xFF; 32]);

        let sig = TrustSignature::new(
            signer_id,
            wrong_signed_id,
            &signed.public_key,
            TRUST_LEVEL_FULL,
            2_000_000,
            &signer.secret_key().unwrap(),
        )
        .unwrap();

        let signer_pk = signer.public_key().unwrap();
        assert!(matches!(
            sig.verify(&signer_pk, Some(1_000_000)),
            Err(WotError::AgentIdMismatch)
        ));
    }

    #[test]
    fn test_trust_signature_invalid_level() {
        let signer = make_keypair();
        let signed = make_keypair();
        let signer_id = AgentId::from_public_key(&signer.public_key);
        let signed_id = AgentId::from_public_key(&signed.public_key);

        let result = TrustSignature::new(
            signer_id,
            signed_id,
            &signed.public_key,
            4, // Invalid
            2_000_000,
            &signer.secret_key().unwrap(),
        );
        assert!(matches!(result, Err(WotError::InvalidTrustLevel(4))));
    }

    #[test]
    fn test_cbor_roundtrip() {
        let signer = make_keypair();
        let signed = make_keypair();
        let signer_id = AgentId::from_public_key(&signer.public_key);
        let signed_id = AgentId::from_public_key(&signed.public_key);

        let sig = TrustSignature::new(
            signer_id,
            signed_id,
            &signed.public_key,
            TRUST_LEVEL_MARGINAL,
            2_000_000,
            &signer.secret_key().unwrap(),
        )
        .unwrap();

        let encoded = sig.encode().unwrap();
        let decoded = TrustSignature::decode(&encoded).unwrap();
        assert_eq!(decoded.sig_type, sig.sig_type);
        assert_eq!(decoded.signer_agent_id, sig.signer_agent_id);
        assert_eq!(decoded.signed_agent_id, sig.signed_agent_id);
        assert_eq!(decoded.signed_public_key, sig.signed_public_key);
        assert_eq!(decoded.trust_level, sig.trust_level);
        assert_eq!(decoded.expiry, sig.expiry);
        assert_eq!(decoded.signature, sig.signature);
    }

    #[test]
    fn test_wot_direct_trust() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let now = 1_000_000u64;
        let mut wot = WebOfTrust::new();
        wot.set_own_agent_id(a_id);

        let sig = TrustSignature::new(
            a_id,
            b_id,
            &b.public_key,
            TRUST_LEVEL_FULL,
            now + 3600,
            &a.secret_key().unwrap(),
        )
        .unwrap();
        wot.add_trust_signature(sig);

        assert_eq!(wot.trust_level(&b_id, now), TRUST_LEVEL_FULL);
        assert!(wot.is_trusted(&b_id, TRUST_LEVEL_MARGINAL, now));
    }

    #[test]
    fn test_wot_transitive_trust() {
        // A trusts B (Full), B trusts C (Full) → A trusts C (Marginal)
        let a = make_keypair();
        let b = make_keypair();
        let c = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);
        let c_id = AgentId::from_public_key(&c.public_key);

        let now = 1_000_000u64;
        let mut wot = WebOfTrust::new();
        wot.set_own_agent_id(a_id);

        // A signs B
        let sig_ab = TrustSignature::new(
            a_id,
            b_id,
            &b.public_key,
            TRUST_LEVEL_FULL,
            now + 3600,
            &a.secret_key().unwrap(),
        )
        .unwrap();
        wot.add_trust_signature(sig_ab);

        // B signs C
        let sig_bc = TrustSignature::new(
            b_id,
            c_id,
            &c.public_key,
            TRUST_LEVEL_FULL,
            now + 3600,
            &b.secret_key().unwrap(),
        )
        .unwrap();
        wot.add_trust_signature(sig_bc);

        // A → C is one hop: Marginal
        assert_eq!(wot.trust_level(&c_id, now), TRUST_LEVEL_MARGINAL);
    }

    #[test]
    fn test_wot_no_trust() {
        let a = make_keypair();
        let c = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let c_id = AgentId::from_public_key(&c.public_key);

        let now = 1_000_000u64;
        let mut wot = WebOfTrust::new();
        wot.set_own_agent_id(a_id);

        // No signatures → no trust
        assert_eq!(wot.trust_level(&c_id, now), TRUST_LEVEL_NONE);
    }

    #[test]
    fn test_wot_ultimate_for_self() {
        let a = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);

        let now = 1_000_000u64;
        let mut wot = WebOfTrust::new();
        wot.set_own_agent_id(a_id);

        assert_eq!(wot.trust_level(&a_id, now), TRUST_LEVEL_ULTIMATE);
    }

    #[test]
    fn test_wot_expired_signature_ignored() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let now = 1_000_000u64;
        let mut wot = WebOfTrust::new();
        wot.set_own_agent_id(a_id);

        let sig = TrustSignature::new(
            a_id,
            b_id,
            &b.public_key,
            TRUST_LEVEL_FULL,
            now - 1, // Expired
            &a.secret_key().unwrap(),
        )
        .unwrap();
        wot.add_trust_signature(sig);

        assert_eq!(wot.trust_level(&b_id, now), TRUST_LEVEL_NONE);
    }

    #[test]
    fn test_wot_export_import() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let now = 1_000_000u64;
        let mut wot = WebOfTrust::new();
        wot.set_own_agent_id(a_id);

        let sig = TrustSignature::new(
            a_id,
            b_id,
            &b.public_key,
            TRUST_LEVEL_FULL,
            now + 3600,
            &a.secret_key().unwrap(),
        )
        .unwrap();
        wot.add_trust_signature(sig);

        let encoded = wot.export_trust().unwrap();
        let mut wot2 = WebOfTrust::new();
        wot2.import_trust(&encoded).unwrap();

        assert_eq!(wot2.signature_count(), 1);
        assert_eq!(wot2.own_agent_id(), Some(&a_id));
        assert_eq!(wot2.trust_level(&b_id, now), TRUST_LEVEL_FULL);
    }

    #[test]
    fn test_wot_evict_expired() {
        let a = make_keypair();
        let b = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);

        let now = 1_000_000u64;
        let mut wot = WebOfTrust::new();
        wot.set_own_agent_id(a_id);

        // Add expired sig
        let sig_expired = TrustSignature::new(
            a_id,
            b_id,
            &b.public_key,
            TRUST_LEVEL_FULL,
            now - 1,
            &a.secret_key().unwrap(),
        )
        .unwrap();
        wot.add_trust_signature(sig_expired);

        assert_eq!(wot.signature_count(), 1);
        let removed = wot.evict_expired(now);
        assert_eq!(removed, 1);
        assert_eq!(wot.signature_count(), 0);
    }

    #[test]
    fn test_wot_two_hops_is_none() {
        // A → B → C → D: two hops from A to D is None
        let a = make_keypair();
        let b = make_keypair();
        let c = make_keypair();
        let d = make_keypair();
        let a_id = AgentId::from_public_key(&a.public_key);
        let b_id = AgentId::from_public_key(&b.public_key);
        let c_id = AgentId::from_public_key(&c.public_key);
        let d_id = AgentId::from_public_key(&d.public_key);

        let now = 1_000_000u64;
        let mut wot = WebOfTrust::new();
        wot.set_own_agent_id(a_id);

        // A → B
        wot.add_trust_signature(
            TrustSignature::new(
                a_id,
                b_id,
                &b.public_key,
                TRUST_LEVEL_FULL,
                now + 3600,
                &a.secret_key().unwrap(),
            )
            .unwrap(),
        );
        // B → C
        wot.add_trust_signature(
            TrustSignature::new(
                b_id,
                c_id,
                &c.public_key,
                TRUST_LEVEL_FULL,
                now + 3600,
                &b.secret_key().unwrap(),
            )
            .unwrap(),
        );
        // C → D
        wot.add_trust_signature(
            TrustSignature::new(
                c_id,
                d_id,
                &d.public_key,
                TRUST_LEVEL_FULL,
                now + 3600,
                &c.secret_key().unwrap(),
            )
            .unwrap(),
        );

        // A → C is one hop: Marginal
        assert_eq!(wot.trust_level(&c_id, now), TRUST_LEVEL_MARGINAL);
        // A → D is two hops: None
        assert_eq!(wot.trust_level(&d_id, now), TRUST_LEVEL_NONE);
    }
}
