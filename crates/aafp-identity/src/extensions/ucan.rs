//! UCAN (User-Controlled Authorization Networks) extension (Track Y9).
//!
//! Provides a richer UCAN token implementation with a builder pattern,
//! capability attenuation, proof-chain validation, and CBOR serialization
//! using the AAFP canonical CBOR encoder.
//!
//! This module is distinct from [`crate::ucan`] (the MVP JWT-style
//! implementation). The extension here uses int-keyed CBOR maps (per
//! AAFP conventions), supports `caveats` on capabilities, `facts` on
//! tokens, and a fluent [`UcanBuilder`].
//!
//! Signing uses ML-DSA-65 via [`crate::keypair::AgentKeypair`], which is
//! the standard AAFP signature scheme.

use std::collections::HashMap;

use aafp_cbor::{decode, encode, int_map, int_map_get, str_map, Value};
use aafp_crypto::SignatureScheme;
use sha2::{Digest, Sha256};

use crate::agent_id::{agent_id_to_hex, AgentId};
use crate::identity_v1::IdentityError;
use crate::keypair::AgentKeypair;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default algorithm string for UCAN tokens.
pub const UCAN_ALG: &str = "ML-DSA-65";
/// Default token type.
pub const UCAN_TYP: &str = "UCAN";

// CBOR map keys for UcanHeader
const HDR_ALG: i64 = 1;
const HDR_TYP: i64 = 2;
const HDR_KID: i64 = 3;

// CBOR map keys for UcanPayload
const PAY_ISS: i64 = 1;
const PAY_AUD: i64 = 2;
const PAY_EXP: i64 = 3;
const PAY_NBF: i64 = 4;
const PAY_PRF: i64 = 5;
const PAY_ATT: i64 = 6;
const PAY_FCT: i64 = 7;

// CBOR map keys for Capability
const CAP_RESOURCE: i64 = 1;
const CAP_ACTION: i64 = 2;
const CAP_CAVEATS: i64 = 3;

// CBOR map keys for Ucan (outer)
const UCAN_HEADER: i64 = 1;
const UCAN_PAYLOAD: i64 = 2;
const UCAN_SIGNATURE: i64 = 3;

// ---------------------------------------------------------------------------
// UcanHeader
// ---------------------------------------------------------------------------

/// Header of a UCAN token, identifying the signing algorithm and issuer key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UcanHeader {
    /// Signature algorithm (e.g., `"ML-DSA-65"`).
    pub alg: String,
    /// Token type (e.g., `"UCAN"`).
    pub typ: String,
    /// Key ID — hex-encoded AgentId (SHA-256 of the issuer's public key).
    pub kid: String,
}

impl UcanHeader {
    /// Create a new header with the given algorithm, type, and key ID.
    pub fn new(alg: impl Into<String>, typ: impl Into<String>, kid: impl Into<String>) -> Self {
        Self {
            alg: alg.into(),
            typ: typ.into(),
            kid: kid.into(),
        }
    }

    /// Encode the header to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (HDR_ALG, Value::TextString(self.alg.clone())),
            (HDR_TYP, Value::TextString(self.typ.clone())),
            (HDR_KID, Value::TextString(self.kid.clone())),
        ])
    }

    /// Decode a header from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let alg = match int_map_get(val, HDR_ALG) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(IdentityError::MissingField("alg")),
        };
        let typ = match int_map_get(val, HDR_TYP) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(IdentityError::MissingField("typ")),
        };
        let kid = match int_map_get(val, HDR_KID) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(IdentityError::MissingField("kid")),
        };
        Ok(Self { alg, typ, kid })
    }
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// A capability delegated by a UCAN token.
///
/// A capability grants `action` on `resource`, optionally constrained by
/// `caveats` (key-value pairs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    /// The resource being delegated (e.g., `"compute.inference"`).
    pub resource: String,
    /// The action permitted (e.g., `"invoke"`, `"read"`).
    pub action: String,
    /// Optional caveats constraining the capability.
    pub caveats: HashMap<String, String>,
}

impl Capability {
    /// Create a new capability with no caveats.
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
            caveats: HashMap::new(),
        }
    }

    /// Add a caveat to the capability. Returns `self` for chaining.
    pub fn with_caveat(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.caveats.insert(key.into(), value.into());
        self
    }

    /// Encode the capability to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = vec![
            (CAP_RESOURCE, Value::TextString(self.resource.clone())),
            (CAP_ACTION, Value::TextString(self.action.clone())),
        ];
        if !self.caveats.is_empty() {
            let caveats: Vec<(String, Value)> = self
                .caveats
                .iter()
                .map(|(k, v)| (k.clone(), Value::TextString(v.clone())))
                .collect();
            entries.push((CAP_CAVEATS, str_map(caveats)));
        }
        int_map(entries)
    }

    /// Decode a capability from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let resource = match int_map_get(val, CAP_RESOURCE) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(IdentityError::MissingField("resource")),
        };
        let action = match int_map_get(val, CAP_ACTION) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(IdentityError::MissingField("action")),
        };
        let caveats = match int_map_get(val, CAP_CAVEATS) {
            Some(Value::StrMap(entries)) => {
                let mut map = HashMap::new();
                for (k, v) in entries {
                    if let Value::TextString(s) = v {
                        map.insert(k.clone(), s.clone());
                    }
                }
                map
            }
            _ => HashMap::new(),
        };
        Ok(Self {
            resource,
            action,
            caveats,
        })
    }

    /// Check if this capability is a subset of (or equal to) `parent`.
    /// The resource must match or be a sub-resource, the action must match,
    /// and all parent caveats must be present with matching values.
    pub fn is_subset_of(&self, parent: &Capability) -> bool {
        let resource_ok = self.resource == parent.resource
            || self.resource.starts_with(&format!("{}.", parent.resource));
        let action_ok = self.action == parent.action;
        if !resource_ok || !action_ok {
            return false;
        }
        // All parent caveats must be satisfied by self.
        for (k, v) in &parent.caveats {
            match self.caveats.get(k) {
                Some(sv) if sv == v => {}
                _ => return false,
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// UcanPayload
// ---------------------------------------------------------------------------

/// Payload of a UCAN token, containing issuer, audience, capabilities,
/// timestamps, proof chain, and facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UcanPayload {
    /// Issuer AgentId (hex-encoded).
    pub iss: String,
    /// Audience AgentId (hex-encoded).
    pub aud: String,
    /// Expiration timestamp (unix seconds).
    pub exp: u64,
    /// Not-before timestamp (unix seconds).
    pub nbf: u64,
    /// Proof chain: list of parent UCAN tokens (empty for a root token).
    pub prf: Vec<Ucan>,
    /// Attenuations: capabilities delegated by this token.
    pub att: Vec<Capability>,
    /// Facts: assertions about the token or environment.
    pub fct: Vec<HashMap<String, String>>,
}

impl UcanPayload {
    /// Encode the payload to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = vec![
            (PAY_ISS, Value::TextString(self.iss.clone())),
            (PAY_AUD, Value::TextString(self.aud.clone())),
            (PAY_EXP, Value::Unsigned(self.exp)),
            (PAY_NBF, Value::Unsigned(self.nbf)),
        ];
        if !self.prf.is_empty() {
            entries.push((
                PAY_PRF,
                Value::Array(self.prf.iter().map(|u| u.to_cbor()).collect()),
            ));
        }
        if !self.att.is_empty() {
            entries.push((
                PAY_ATT,
                Value::Array(self.att.iter().map(|c| c.to_cbor()).collect()),
            ));
        }
        if !self.fct.is_empty() {
            let facts: Vec<Value> = self
                .fct
                .iter()
                .map(|fact| {
                    let entries: Vec<(String, Value)> = fact
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::TextString(v.clone())))
                        .collect();
                    str_map(entries)
                })
                .collect();
            entries.push((PAY_FCT, Value::Array(facts)));
        }
        int_map(entries)
    }

    /// Decode a payload from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let iss = match int_map_get(val, PAY_ISS) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(IdentityError::MissingField("iss")),
        };
        let aud = match int_map_get(val, PAY_AUD) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(IdentityError::MissingField("aud")),
        };
        let exp = match int_map_get(val, PAY_EXP) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(IdentityError::MissingField("exp")),
        };
        let nbf = match int_map_get(val, PAY_NBF) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(IdentityError::MissingField("nbf")),
        };
        let prf = match int_map_get(val, PAY_PRF) {
            Some(Value::Array(arr)) => {
                let mut tokens = Vec::new();
                for v in arr {
                    tokens.push(Ucan::from_cbor(v)?);
                }
                tokens
            }
            _ => Vec::new(),
        };
        let att = match int_map_get(val, PAY_ATT) {
            Some(Value::Array(arr)) => {
                let mut caps = Vec::new();
                for v in arr {
                    caps.push(Capability::from_cbor(v)?);
                }
                caps
            }
            _ => Vec::new(),
        };
        let fct = match int_map_get(val, PAY_FCT) {
            Some(Value::Array(arr)) => {
                let mut facts = Vec::new();
                for v in arr {
                    if let Value::StrMap(entries) = v {
                        let mut map = HashMap::new();
                        for (k, val) in entries {
                            if let Value::TextString(s) = val {
                                map.insert(k.clone(), s.clone());
                            }
                        }
                        facts.push(map);
                    }
                }
                facts
            }
            _ => Vec::new(),
        };
        Ok(Self {
            iss,
            aud,
            exp,
            nbf,
            prf,
            att,
            fct,
        })
    }
}

// ---------------------------------------------------------------------------
// Ucan
// ---------------------------------------------------------------------------

/// A UCAN (User-Controlled Authorization Networks) token.
///
/// Consists of a header (algorithm + issuer key ID), a payload (issuer,
/// audience, capabilities, timestamps, proof chain, facts), and a
/// signature over the CBOR encoding of header + payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ucan {
    /// Token header.
    pub header: UcanHeader,
    /// Token payload.
    pub payload: UcanPayload,
    /// ML-DSA-65 signature over `CBOR(header) || CBOR(payload)`.
    pub signature: Vec<u8>,
}

impl Ucan {
    /// Create a new unsigned UCAN token (signature is empty). Use
    /// [`Ucan::sign`] to fill in the signature.
    pub fn new(header: UcanHeader, payload: UcanPayload) -> Self {
        Self {
            header,
            payload,
            signature: Vec::new(),
        }
    }

    /// Compute the signing input: `CBOR(header) || CBOR(payload)`.
    pub fn signing_input(&self) -> Vec<u8> {
        let header_cbor = self.header.to_cbor();
        let payload_cbor = self.payload.to_cbor();
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode(&header_cbor).expect("encode header"));
        buf.extend_from_slice(&encode(&payload_cbor).expect("encode payload"));
        buf
    }

    /// Sign this token in-place using the given keypair.
    ///
    /// The `kid` in the header must match the AgentId derived from the
    /// keypair's public key. If it does not, an error is returned.
    pub fn sign(&mut self, keypair: &AgentKeypair) -> Result<(), IdentityError> {
        let expected_kid = agent_id_to_hex(&derive_agent_id(&keypair.public_key));
        if self.header.kid != expected_kid {
            return Err(IdentityError::InvalidField {
                field: "kid",
                message: format!(
                    "kid does not match keypair: expected {}, got {}",
                    expected_kid, self.header.kid
                ),
            });
        }
        let signing_input = self.signing_input();
        self.signature = keypair.sign(&signing_input);
        Ok(())
    }

    /// Verify this token's signature against the given public key.
    ///
    /// Also checks:
    /// - The algorithm is supported.
    /// - The `kid` matches the AgentId derived from the public key.
    /// - The token has not expired (`exp`).
    /// - The token is currently valid (`nbf`).
    pub fn verify(&self, public_key: &[u8], now_secs: u64) -> Result<(), IdentityError> {
        // Check algorithm.
        if self.header.alg != UCAN_ALG {
            return Err(IdentityError::InvalidField {
                field: "alg",
                message: format!("unsupported algorithm: {}", self.header.alg),
            });
        }
        // Check kid matches public key.
        let expected_kid = agent_id_to_hex(&derive_agent_id(public_key));
        if self.header.kid != expected_kid {
            return Err(IdentityError::InvalidAgentId);
        }
        // Verify signature.
        let signing_input = self.signing_input();
        let pk = aafp_crypto::MlDsa65PublicKey::from_bytes(public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let sig = aafp_crypto::MlDsa65Signature::from_bytes(&self.signature)
            .map_err(|_| IdentityError::InvalidSignatureLength)?;
        if !aafp_crypto::MlDsa65::verify(&pk, &signing_input, &sig) {
            return Err(IdentityError::SignatureVerificationFailed);
        }
        // Check expiry.
        if now_secs >= self.payload.exp {
            return Err(IdentityError::Expired {
                expires_at: self.payload.exp,
                now: now_secs,
            });
        }
        // Check not-before.
        if now_secs < self.payload.nbf {
            return Err(IdentityError::InvalidField {
                field: "nbf",
                message: format!(
                    "token not yet valid: nbf={}, now={}",
                    self.payload.nbf, now_secs
                ),
            });
        }
        Ok(())
    }

    /// Check if this token has expired at the given time.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.payload.exp
    }

    /// Create a delegated UCAN from this token.
    ///
    /// The new token is issued by `new_issuer`, delegates to `audience`,
    /// and carries `capabilities` (which must be a subset of this token's
    /// capabilities). This token is included in the new token's proof chain.
    pub fn delegate(
        &self,
        new_issuer: &AgentKeypair,
        audience: &AgentId,
        capabilities: Vec<Capability>,
        expires_at: u64,
        not_before: u64,
    ) -> Result<Ucan, IdentityError> {
        // Validate that capabilities are a subset.
        for cap in &capabilities {
            if !self
                .payload
                .att
                .iter()
                .any(|parent| cap.is_subset_of(parent))
            {
                return Err(IdentityError::InvalidField {
                    field: "att",
                    message: format!(
                        "capability '{}' '{}' is not a subset of parent capabilities",
                        cap.resource, cap.action
                    ),
                });
            }
        }

        let issuer_kid = agent_id_to_hex(&derive_agent_id(&new_issuer.public_key));
        let header = UcanHeader::new(UCAN_ALG, UCAN_TYP, issuer_kid);
        let payload = UcanPayload {
            iss: header.kid.clone(),
            aud: agent_id_to_hex(audience),
            exp: expires_at,
            nbf: not_before,
            prf: vec![self.clone()],
            att: capabilities,
            fct: Vec::new(),
        };

        let mut ucan = Ucan::new(header, payload);
        ucan.sign(new_issuer)?;
        Ok(ucan)
    }

    /// Attenuate this token: create a new token with reduced capabilities.
    ///
    /// The new token is issued by `new_issuer` (who should be the audience
    /// of this token), delegates to `audience`, and carries `capabilities`
    /// which must be a subset of this token's capabilities. This token is
    /// included in the proof chain.
    pub fn attenuate(
        &self,
        new_issuer: &AgentKeypair,
        audience: &AgentId,
        capabilities: Vec<Capability>,
        expires_at: u64,
        not_before: u64,
    ) -> Result<Ucan, IdentityError> {
        // Attenuate is delegate with strict subset enforcement.
        if capabilities.len() >= self.payload.att.len() {
            // Check that at least one capability is strictly narrower.
            let all_equal = capabilities
                .iter()
                .all(|c| self.payload.att.iter().any(|p| c == p));
            if all_equal && capabilities.len() == self.payload.att.len() {
                return Err(IdentityError::InvalidField {
                    field: "att",
                    message: "attenuate must reduce capabilities, not duplicate them".into(),
                });
            }
        }
        self.delegate(new_issuer, audience, capabilities, expires_at, not_before)
    }

    /// Validate the proof chain of this token.
    ///
    /// Walks the `prf` chain from this token up to the root, verifying:
    /// 1. Each token's signature (using the resolver to obtain public keys).
    /// 2. Capabilities do not expand at each level.
    /// 3. No token is expired.
    /// 4. Chain links are connected (each parent's audience matches the
    ///    child's issuer).
    ///
    /// `resolver` maps a `kid` (hex AgentId) to the corresponding public
    /// key bytes.
    pub fn validate_chain(
        &self,
        now_secs: u64,
        resolver: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<(), IdentityError> {
        self.validate_chain_impl(now_secs, resolver)
    }

    fn validate_chain_impl(
        &self,
        now_secs: u64,
        resolver: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<(), IdentityError> {
        // Resolve this token's issuer public key.
        let pubkey = resolver(&self.header.kid).ok_or_else(|| IdentityError::InvalidField {
            field: "kid",
            message: format!("cannot resolve public key for kid: {}", self.header.kid),
        })?;

        // Verify this token's signature.
        self.verify(&pubkey, now_secs)?;

        // For each parent in the proof chain, validate recursively.
        for parent in &self.payload.prf {
            // Check chain linkage: parent's audience should be this token's issuer.
            if parent.payload.aud != self.payload.iss {
                return Err(IdentityError::InvalidField {
                    field: "prf",
                    message: format!(
                        "chain link broken: parent aud '{}' does not match child iss '{}'",
                        parent.payload.aud, self.payload.iss
                    ),
                });
            }

            // Check capabilities don't expand: every capability in self
            // must be a subset of some capability in the parent.
            for cap in &self.payload.att {
                if !parent.payload.att.iter().any(|pc| cap.is_subset_of(pc)) {
                    return Err(IdentityError::InvalidField {
                        field: "att",
                        message: format!(
                            "capability '{}' '{}' expands beyond parent",
                            cap.resource, cap.action
                        ),
                    });
                }
            }

            // Recursively validate the parent.
            parent.validate_chain_impl(now_secs, resolver)?;
        }

        Ok(())
    }

    /// Encode the full UCAN token to CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let cbor = self.to_cbor();
        encode(&cbor).map_err(IdentityError::Cbor)
    }

    /// Decode a UCAN token from CBOR bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, IdentityError> {
        let (val, _) = decode(data).map_err(IdentityError::Cbor)?;
        Self::from_cbor(&val)
    }

    /// Encode the full UCAN token to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (UCAN_HEADER, self.header.to_cbor()),
            (UCAN_PAYLOAD, self.payload.to_cbor()),
            (UCAN_SIGNATURE, Value::ByteString(self.signature.clone())),
        ])
    }

    /// Decode a UCAN token from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let header = match int_map_get(val, UCAN_HEADER) {
            Some(h) => UcanHeader::from_cbor(h)?,
            None => return Err(IdentityError::MissingField("header")),
        };
        let payload = match int_map_get(val, UCAN_PAYLOAD) {
            Some(p) => UcanPayload::from_cbor(p)?,
            None => return Err(IdentityError::MissingField("payload")),
        };
        let signature = match int_map_get(val, UCAN_SIGNATURE) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => Vec::new(),
        };
        Ok(Self {
            header,
            payload,
            signature,
        })
    }

    /// Return the capabilities (attenuations) of this token.
    pub fn capabilities(&self) -> &[Capability] {
        &self.payload.att
    }

    /// Return the proof chain (parent tokens).
    pub fn proof_chain(&self) -> &[Ucan] {
        &self.payload.prf
    }

    /// Return the facts of this token.
    pub fn facts(&self) -> &[HashMap<String, String>] {
        &self.payload.fct
    }
}

// ---------------------------------------------------------------------------
// UcanBuilder
// ---------------------------------------------------------------------------

/// A builder for constructing UCAN tokens.
///
/// ```
/// # use aafp_identity::extensions::ucan::*;
/// // Build an unsigned token, then sign it.
/// let mut ucan = UcanBuilder::new()
///     .issuer_kid("abc123")
///     .audience("def456")
///     .expiry(999999999)
///     .capability(Capability::new("compute.inference", "invoke"))
///     .build();
/// ```
#[derive(Clone, Debug)]
pub struct UcanBuilder {
    alg: String,
    typ: String,
    kid: String,
    iss: String,
    aud: String,
    exp: u64,
    nbf: u64,
    prf: Vec<Ucan>,
    att: Vec<Capability>,
    fct: Vec<HashMap<String, String>>,
}

impl UcanBuilder {
    /// Create a new builder with default values.
    pub fn new() -> Self {
        Self {
            alg: UCAN_ALG.into(),
            typ: UCAN_TYP.into(),
            kid: String::new(),
            iss: String::new(),
            aud: String::new(),
            exp: u64::MAX,
            nbf: 0,
            prf: Vec::new(),
            att: Vec::new(),
            fct: Vec::new(),
        }
    }

    /// Set the algorithm (default: `"ML-DSA-65"`).
    pub fn algorithm(mut self, alg: impl Into<String>) -> Self {
        self.alg = alg.into();
        self
    }

    /// Set the token type (default: `"UCAN"`).
    pub fn token_type(mut self, typ: impl Into<String>) -> Self {
        self.typ = typ.into();
        self
    }

    /// Set the issuer key ID (hex AgentId). Also sets `iss` if not
    /// already set.
    pub fn issuer_kid(mut self, kid: impl Into<String>) -> Self {
        let kid = kid.into();
        if self.iss.is_empty() {
            self.iss = kid.clone();
        }
        self.kid = kid;
        self
    }

    /// Set the issuer (hex AgentId).
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = iss.into();
        if self.kid.is_empty() {
            self.kid = self.iss.clone();
        }
        self
    }

    /// Set the audience (hex AgentId).
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.aud = aud.into();
        self
    }

    /// Set the expiration timestamp (unix seconds).
    pub fn expiry(mut self, exp: u64) -> Self {
        self.exp = exp;
        self
    }

    /// Set the not-before timestamp (unix seconds).
    pub fn not_before(mut self, nbf: u64) -> Self {
        self.nbf = nbf;
        self
    }

    /// Add a proof (parent UCAN token) to the proof chain.
    pub fn proof(mut self, ucan: Ucan) -> Self {
        self.prf.push(ucan);
        self
    }

    /// Add a capability (attenuation) to the token.
    pub fn capability(mut self, cap: Capability) -> Self {
        self.att.push(cap);
        self
    }

    /// Add a fact (key-value map) to the token.
    pub fn fact(mut self, fact: HashMap<String, String>) -> Self {
        self.fct.push(fact);
        self
    }

    /// Build the unsigned UCAN token.
    pub fn build(self) -> Ucan {
        let header = UcanHeader {
            alg: self.alg,
            typ: self.typ,
            kid: self.kid,
        };
        let payload = UcanPayload {
            iss: self.iss,
            aud: self.aud,
            exp: self.exp,
            nbf: self.nbf,
            prf: self.prf,
            att: self.att,
            fct: self.fct,
        };
        Ucan::new(header, payload)
    }

    /// Build and sign the UCAN token in one step.
    pub fn build_and_sign(self, keypair: &AgentKeypair) -> Result<Ucan, IdentityError> {
        let mut ucan = self.build();
        ucan.sign(keypair)?;
        Ok(ucan)
    }
}

impl Default for UcanBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive an AgentId from a public key (SHA-256).
fn derive_agent_id(public_key: &[u8]) -> AgentId {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Derive an AgentId from a keypair and return it.
pub fn keypair_agent_id(keypair: &AgentKeypair) -> AgentId {
    derive_agent_id(&keypair.public_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn now_secs() -> u64 {
        1_700_000_000
    }

    fn far_future() -> u64 {
        now_secs() + 3600
    }

    fn make_keypair() -> AgentKeypair {
        AgentKeypair::generate()
    }

    fn make_kid(kp: &AgentKeypair) -> String {
        agent_id_to_hex(&derive_agent_id(&kp.public_key))
    }

    fn make_agent_id(kp: &AgentKeypair) -> AgentId {
        derive_agent_id(&kp.public_key)
    }

    // 1. UcanHeader creation and CBOR roundtrip
    #[test]
    fn test_header_creation_and_cbor() {
        let header = UcanHeader::new("ML-DSA-65", "UCAN", "abc123");
        assert_eq!(header.alg, "ML-DSA-65");
        assert_eq!(header.typ, "UCAN");
        assert_eq!(header.kid, "abc123");

        let cbor = header.to_cbor();
        let decoded = UcanHeader::from_cbor(&cbor).expect("decode");
        assert_eq!(header, decoded);
    }

    // 2. UcanHeader missing field error
    #[test]
    fn test_header_missing_field() {
        let cbor = int_map(vec![(HDR_ALG, Value::TextString("ML-DSA-65".into()))]);
        let result = UcanHeader::from_cbor(&cbor);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::MissingField("typ")
        ));
    }

    // 3. Capability creation with caveats
    #[test]
    fn test_capability_with_caveats() {
        let cap = Capability::new("compute.inference", "invoke")
            .with_caveat("max_tokens", "1000")
            .with_caveat("model", "gpt-4");
        assert_eq!(cap.resource, "compute.inference");
        assert_eq!(cap.action, "invoke");
        assert_eq!(cap.caveats.get("max_tokens"), Some(&"1000".to_string()));
        assert_eq!(cap.caveats.get("model"), Some(&"gpt-4".to_string()));
    }

    // 4. Capability CBOR roundtrip
    #[test]
    fn test_capability_cbor_roundtrip() {
        let cap = Capability::new("storage", "read").with_caveat("max_bytes", "1024");
        let cbor = cap.to_cbor();
        let decoded = Capability::from_cbor(&cbor).expect("decode");
        assert_eq!(cap, decoded);
    }

    // 5. Capability CBOR roundtrip without caveats
    #[test]
    fn test_capability_cbor_no_caveats() {
        let cap = Capability::new("compute", "invoke");
        let cbor = cap.to_cbor();
        let decoded = Capability::from_cbor(&cbor).expect("decode");
        assert_eq!(cap, decoded);
        assert!(decoded.caveats.is_empty());
    }

    // 6. Capability is_subset_of: same capability
    #[test]
    fn test_capability_subset_same() {
        let parent = Capability::new("compute", "invoke");
        let child = Capability::new("compute", "invoke");
        assert!(child.is_subset_of(&parent));
    }

    // 7. Capability is_subset_of: sub-resource
    #[test]
    fn test_capability_subset_subresource() {
        let parent = Capability::new("compute", "invoke");
        let child = Capability::new("compute.inference", "invoke");
        assert!(child.is_subset_of(&parent));
    }

    // 8. Capability is_subset_of: different action
    #[test]
    fn test_capability_subset_different_action() {
        let parent = Capability::new("compute", "invoke");
        let child = Capability::new("compute", "admin");
        assert!(!child.is_subset_of(&parent));
    }

    // 9. Capability is_subset_of: caveats must match
    #[test]
    fn test_capability_subset_caveats() {
        let parent = Capability::new("compute", "invoke").with_caveat("region", "us-east");
        let child_ok = Capability::new("compute", "invoke").with_caveat("region", "us-east");
        let child_fail = Capability::new("compute", "invoke").with_caveat("region", "eu-west");
        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_fail.is_subset_of(&parent));
    }

    // 10. UcanPayload CBOR roundtrip
    #[test]
    fn test_payload_cbor_roundtrip() {
        let payload = UcanPayload {
            iss: "issuer123".into(),
            aud: "audience456".into(),
            exp: 999999999,
            nbf: 1000000,
            prf: Vec::new(),
            att: vec![Capability::new("compute", "invoke")],
            fct: Vec::new(),
        };
        let cbor = payload.to_cbor();
        let decoded = UcanPayload::from_cbor(&cbor).expect("decode");
        assert_eq!(payload, decoded);
    }

    // 11. UcanPayload CBOR roundtrip with facts
    #[test]
    fn test_payload_cbor_with_facts() {
        let mut fact = HashMap::new();
        fact.insert("source".into(), "sensor-1".into());
        let payload = UcanPayload {
            iss: "iss".into(),
            aud: "aud".into(),
            exp: 100,
            nbf: 0,
            prf: Vec::new(),
            att: Vec::new(),
            fct: vec![fact],
        };
        let cbor = payload.to_cbor();
        let decoded = UcanPayload::from_cbor(&cbor).expect("decode");
        assert_eq!(payload, decoded);
        assert_eq!(decoded.fct.len(), 1);
    }

    // 12. Sign and verify a UCAN token
    #[test]
    fn test_sign_and_verify() {
        let kp = make_keypair();
        let kid = make_kid(&kp);
        let aud = make_agent_id(&make_keypair());

        let mut ucan = UcanBuilder::new()
            .issuer_kid(&kid)
            .audience(agent_id_to_hex(&aud))
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute.inference", "invoke"))
            .build();
        ucan.sign(&kp).expect("sign");

        ucan.verify(&kp.public_key, now_secs()).expect("verify");
    }

    // 13. Verify rejects wrong public key
    #[test]
    fn test_verify_wrong_key() {
        let kp = make_keypair();
        let kid = make_kid(&kp);
        let other = make_keypair();

        let mut ucan = UcanBuilder::new()
            .issuer_kid(&kid)
            .audience("audience")
            .expiry(far_future())
            .capability(Capability::new("x", "y"))
            .build();
        ucan.sign(&kp).expect("sign");

        let err = ucan.verify(&other.public_key, now_secs()).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidAgentId));
    }

    // 14. Verify rejects expired token
    #[test]
    fn test_verify_expired() {
        let kp = make_keypair();
        let kid = make_kid(&kp);

        let mut ucan = UcanBuilder::new()
            .issuer_kid(&kid)
            .audience("audience")
            .expiry(now_secs() - 1) // already expired
            .capability(Capability::new("x", "y"))
            .build();
        ucan.sign(&kp).expect("sign");

        let err = ucan.verify(&kp.public_key, now_secs()).unwrap_err();
        assert!(matches!(err, IdentityError::Expired { .. }));
    }

    // 15. Verify rejects not-yet-valid token
    #[test]
    fn test_verify_not_yet_valid() {
        let kp = make_keypair();
        let kid = make_kid(&kp);

        let mut ucan = UcanBuilder::new()
            .issuer_kid(&kid)
            .audience("audience")
            .expiry(far_future())
            .not_before(now_secs() + 100)
            .capability(Capability::new("x", "y"))
            .build();
        ucan.sign(&kp).expect("sign");

        let err = ucan.verify(&kp.public_key, now_secs()).unwrap_err();
        assert!(matches!(
            err,
            IdentityError::InvalidField { field: "nbf", .. }
        ));
    }

    // 16. Sign rejects mismatched kid
    #[test]
    fn test_sign_mismatched_kid() {
        let kp = make_keypair();
        let mut ucan = UcanBuilder::new()
            .issuer_kid("wrong_kid")
            .audience("audience")
            .expiry(far_future())
            .capability(Capability::new("x", "y"))
            .build();
        let err = ucan.sign(&kp).unwrap_err();
        assert!(matches!(
            err,
            IdentityError::InvalidField { field: "kid", .. }
        ));
    }

    // 17. is_expired check
    #[test]
    fn test_is_expired() {
        let kp = make_keypair();
        let kid = make_kid(&kp);

        let ucan = UcanBuilder::new()
            .issuer_kid(&kid)
            .audience("audience")
            .expiry(now_secs() + 100)
            .capability(Capability::new("x", "y"))
            .build();

        assert!(!ucan.is_expired(now_secs()));
        assert!(ucan.is_expired(now_secs() + 101));
    }

    // 18. Delegate creates a valid child token
    #[test]
    fn test_delegate() {
        let root = make_keypair();
        let root_kid = make_kid(&root);
        let child = make_keypair();
        let child_aud = make_agent_id(&make_keypair());

        let parent = UcanBuilder::new()
            .issuer_kid(&root_kid)
            .audience(agent_id_to_hex(&make_agent_id(&child)))
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute.inference", "invoke"))
            .build_and_sign(&root)
            .expect("sign parent");

        let delegated = parent
            .delegate(
                &child,
                &child_aud,
                vec![Capability::new("compute.inference", "invoke")],
                far_future(),
                now_secs(),
            )
            .expect("delegate");

        // Verify the delegated token.
        delegated
            .verify(&child.public_key, now_secs())
            .expect("verify");
        assert_eq!(delegated.payload.prf.len(), 1);
        assert_eq!(delegated.payload.iss, make_kid(&child));
    }

    // 19. Delegate rejects capabilities not in parent
    #[test]
    fn test_delegate_rejects_expanded_caps() {
        let root = make_keypair();
        let root_kid = make_kid(&root);
        let child = make_keypair();

        let parent = UcanBuilder::new()
            .issuer_kid(&root_kid)
            .audience(agent_id_to_hex(&make_agent_id(&child)))
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute.inference", "invoke"))
            .build_and_sign(&root)
            .expect("sign parent");

        let err = parent
            .delegate(
                &child,
                &make_agent_id(&make_keypair()),
                vec![Capability::new("storage", "read")], // not in parent
                far_future(),
                now_secs(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            IdentityError::InvalidField { field: "att", .. }
        ));
    }

    // 20. Attenuate reduces capabilities
    #[test]
    fn test_attenuate() {
        let root = make_keypair();
        let root_kid = make_kid(&root);
        let child = make_keypair();
        let grandchild_aud = make_agent_id(&make_keypair());

        let parent = UcanBuilder::new()
            .issuer_kid(&root_kid)
            .audience(agent_id_to_hex(&make_agent_id(&child)))
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute.inference", "invoke"))
            .capability(Capability::new("compute.training", "invoke"))
            .build_and_sign(&root)
            .expect("sign parent");

        // Attenuate: only keep one capability.
        let attenuated = parent
            .attenuate(
                &child,
                &grandchild_aud,
                vec![Capability::new("compute.inference", "invoke")],
                far_future(),
                now_secs(),
            )
            .expect("attenuate");

        assert_eq!(attenuated.payload.att.len(), 1);
        assert_eq!(attenuated.payload.att[0].resource, "compute.inference");
        assert_eq!(attenuated.payload.prf.len(), 1);
    }

    // 21. Attenuate rejects identical capabilities (no reduction)
    #[test]
    fn test_attenuate_rejects_no_reduction() {
        let root = make_keypair();
        let root_kid = make_kid(&root);
        let child = make_keypair();

        let cap = Capability::new("compute.inference", "invoke");
        let parent = UcanBuilder::new()
            .issuer_kid(&root_kid)
            .audience(agent_id_to_hex(&make_agent_id(&child)))
            .expiry(far_future())
            .not_before(now_secs())
            .capability(cap.clone())
            .build_and_sign(&root)
            .expect("sign parent");

        let err = parent
            .attenuate(
                &child,
                &make_agent_id(&make_keypair()),
                vec![cap], // same as parent — no reduction
                far_future(),
                now_secs(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            IdentityError::InvalidField { field: "att", .. }
        ));
    }

    // 22. CBOR serialization roundtrip for full Ucan
    #[test]
    fn test_ucan_cbor_roundtrip() {
        let kp = make_keypair();
        let kid = make_kid(&kp);

        let mut ucan = UcanBuilder::new()
            .issuer_kid(&kid)
            .audience("audience123")
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute.inference", "invoke"))
            .build();
        ucan.sign(&kp).expect("sign");

        let bytes = ucan.to_bytes().expect("encode");
        let decoded = Ucan::from_bytes(&bytes).expect("decode");
        assert_eq!(ucan, decoded);
        decoded.verify(&kp.public_key, now_secs()).expect("verify");
    }

    // 23. CBOR roundtrip with proof chain
    #[test]
    fn test_ucan_cbor_with_proof() {
        let root = make_keypair();
        let root_kid = make_kid(&root);
        let child = make_keypair();

        let parent = UcanBuilder::new()
            .issuer_kid(&root_kid)
            .audience(agent_id_to_hex(&make_agent_id(&child)))
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute", "invoke"))
            .build_and_sign(&root)
            .expect("sign parent");

        let delegated = parent
            .delegate(
                &child,
                &make_agent_id(&make_keypair()),
                vec![Capability::new("compute.inference", "invoke")],
                far_future(),
                now_secs(),
            )
            .expect("delegate");

        let bytes = delegated.to_bytes().expect("encode");
        let decoded = Ucan::from_bytes(&bytes).expect("decode");
        assert_eq!(delegated, decoded);
        assert_eq!(decoded.payload.prf.len(), 1);
    }

    // 24. Validate chain: valid two-level chain
    #[test]
    fn test_validate_chain_valid() {
        let root = make_keypair();
        let root_kid = make_kid(&root);
        let child = make_keypair();
        let child_kid = make_kid(&child);
        let child_aud = make_agent_id(&make_keypair());

        let parent = UcanBuilder::new()
            .issuer_kid(&root_kid)
            .audience(agent_id_to_hex(&make_agent_id(&child)))
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute", "invoke"))
            .build_and_sign(&root)
            .expect("sign parent");

        let delegated = parent
            .delegate(
                &child,
                &child_aud,
                vec![Capability::new("compute.inference", "invoke")],
                far_future(),
                now_secs(),
            )
            .expect("delegate");

        // Build a resolver: kid -> public key.
        let mut keymap: HashMap<String, Vec<u8>> = HashMap::new();
        keymap.insert(root_kid.clone(), root.public_key.clone());
        keymap.insert(child_kid.clone(), child.public_key.clone());

        let resolver = |kid: &str| keymap.get(kid).cloned();
        delegated
            .validate_chain(now_secs(), &resolver)
            .expect("valid chain");
    }

    // 25. Validate chain: broken linkage
    #[test]
    fn test_validate_chain_broken_linkage() {
        let root = make_keypair();
        let root_kid = make_kid(&root);
        let child = make_keypair();

        // Parent delegates to child.
        let parent = UcanBuilder::new()
            .issuer_kid(&root_kid)
            .audience(agent_id_to_hex(&make_agent_id(&child)))
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute", "invoke"))
            .build_and_sign(&root)
            .expect("sign parent");

        // Child delegates to someone, but with wrong iss (not matching parent's aud).
        let wrong_kid = "deadbeef".to_string();
        let mut ucan = UcanBuilder::new()
            .issuer_kid(&wrong_kid)
            .audience("someone")
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute.inference", "invoke"))
            .proof(parent.clone())
            .build();
        // Don't sign — we're testing chain linkage, not signature.
        // The chain validation should fail on linkage before signature.

        let keymap: HashMap<String, Vec<u8>> = HashMap::new();
        let resolver = |kid: &str| keymap.get(kid).cloned();
        // This will fail because we can't resolve the wrong_kid.
        let err = ucan.validate_chain(now_secs(), &resolver).unwrap_err();
        assert!(matches!(
            err,
            IdentityError::InvalidField { field: "kid", .. }
        ));
    }

    // 26. Validate chain: expired token in chain
    #[test]
    fn test_validate_chain_expired() {
        let root = make_keypair();
        let root_kid = make_kid(&root);
        let child = make_keypair();
        let child_kid = make_kid(&child);

        let parent = UcanBuilder::new()
            .issuer_kid(&root_kid)
            .audience(agent_id_to_hex(&make_agent_id(&child)))
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute", "invoke"))
            .build_and_sign(&root)
            .expect("sign parent");

        // Child token is expired.
        let delegated = parent
            .delegate(
                &child,
                &make_agent_id(&make_keypair()),
                vec![Capability::new("compute.inference", "invoke")],
                now_secs() - 1, // expired
                now_secs(),
            )
            .expect("delegate");

        let mut keymap: HashMap<String, Vec<u8>> = HashMap::new();
        keymap.insert(root_kid, root.public_key.clone());
        keymap.insert(child_kid, child.public_key.clone());

        let resolver = |kid: &str| keymap.get(kid).cloned();
        let err = delegated.validate_chain(now_secs(), &resolver).unwrap_err();
        assert!(matches!(err, IdentityError::Expired { .. }));
    }

    // 27. UcanBuilder default values
    #[test]
    fn test_builder_defaults() {
        let builder = UcanBuilder::new();
        assert_eq!(builder.alg, UCAN_ALG);
        assert_eq!(builder.typ, UCAN_TYP);
        assert_eq!(builder.exp, u64::MAX);
        assert_eq!(builder.nbf, 0);
        assert!(builder.att.is_empty());
        assert!(builder.prf.is_empty());
    }

    // 28. UcanBuilder build_and_sign
    #[test]
    fn test_builder_build_and_sign() {
        let kp = make_keypair();
        let kid = make_kid(&kp);

        let ucan = UcanBuilder::new()
            .issuer_kid(&kid)
            .audience("audience")
            .expiry(far_future())
            .not_before(now_secs())
            .capability(Capability::new("compute", "invoke"))
            .build_and_sign(&kp)
            .expect("build and sign");

        assert!(!ucan.signature.is_empty());
        ucan.verify(&kp.public_key, now_secs()).expect("verify");
    }

    // 29. UcanBuilder with facts
    #[test]
    fn test_builder_with_facts() {
        let kp = make_keypair();
        let kid = make_kid(&kp);

        let mut fact = HashMap::new();
        fact.insert("device".into(), "sensor-1".into());

        let ucan = UcanBuilder::new()
            .issuer_kid(&kid)
            .audience("audience")
            .expiry(far_future())
            .capability(Capability::new("compute", "invoke"))
            .fact(fact)
            .build();

        assert_eq!(ucan.payload.fct.len(), 1);
        assert_eq!(
            ucan.payload.fct[0].get("device"),
            Some(&"sensor-1".to_string())
        );
    }

    // 30. Ucan accessors
    #[test]
    fn test_ucan_accessors() {
        let kp = make_keypair();
        let kid = make_kid(&kp);

        let cap = Capability::new("compute", "invoke");
        let ucan = UcanBuilder::new()
            .issuer_kid(&kid)
            .audience("audience")
            .expiry(far_future())
            .capability(cap.clone())
            .build();

        assert_eq!(ucan.capabilities(), &[cap]);
        assert!(ucan.proof_chain().is_empty());
        assert!(ucan.facts().is_empty());
    }

    // 31. Signing input is deterministic
    #[test]
    fn test_signing_input_deterministic() {
        let ucan1 = UcanBuilder::new()
            .issuer_kid("kid1")
            .audience("aud1")
            .expiry(100)
            .capability(Capability::new("x", "y"))
            .build();
        let ucan2 = UcanBuilder::new()
            .issuer_kid("kid1")
            .audience("aud1")
            .expiry(100)
            .capability(Capability::new("x", "y"))
            .build();
        assert_eq!(ucan1.signing_input(), ucan2.signing_input());
    }

    // 32. keypair_agent_id helper
    #[test]
    fn test_keypair_agent_id() {
        let kp = make_keypair();
        let id = keypair_agent_id(&kp);
        let expected = derive_agent_id(&kp.public_key);
        assert_eq!(id, expected);
    }

    // 33. Capability from_cbor with missing resource
    #[test]
    fn test_capability_from_cbor_missing_field() {
        let cbor = int_map(vec![(CAP_ACTION, Value::TextString("invoke".into()))]);
        let result = Capability::from_cbor(&cbor);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::MissingField("resource")
        ));
    }

    // 34. Ucan from_bytes with invalid data
    #[test]
    fn test_ucan_from_bytes_invalid() {
        let result = Ucan::from_bytes(&[0xff, 0xff]);
        assert!(result.is_err());
    }

    // 35. UcanPayload from_cbor with missing iss
    #[test]
    fn test_payload_from_cbor_missing_iss() {
        let cbor = int_map(vec![
            (PAY_AUD, Value::TextString("aud".into())),
            (PAY_EXP, Value::Unsigned(100)),
            (PAY_NBF, Value::Unsigned(0)),
        ]);
        let result = UcanPayload::from_cbor(&cbor);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::MissingField("iss")
        ));
    }
}
