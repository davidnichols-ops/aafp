//! AAFP v1 Handshake Protocol (RFC-0002 §5).
//!
//! Three-way application-layer handshake over QUIC stream 0:
//!   1. ClientHello → ServerHello → ClientFinished
//!
//! All signatures use domain separator `"aafp-v1-handshake"` and are
//! computed over the running transcript hash (SHA-256).
//!
//! ## Transcript Hash (RFC-0002 §5.6)
//!
//! ```text
//! h = SHA-256(tls_binding)
//! h = SHA-256(h || canonical_CBOR(ClientHello_without_sig_and_mac))
//! h = SHA-256(h || canonical_CBOR(ServerHello_without_sig))
//! h = SHA-256(h || canonical_CBOR(ClientFinished_without_sig))
//! ```
//!
//! Each signature is over `"aafp-v1-handshake" || h` where `h` is the
//! transcript hash AFTER folding in the current message.

use crate::dsa::{MlDsa65, MlDsa65PublicKey, MlDsa65Signature};
use crate::kdf::hkdf_sha256;
use crate::traits::SignatureScheme;
use aafp_cbor::{int_map, Value};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Domain separator for handshake signatures (RFC-0003 §3.5).
pub const DOMAIN_SEPARATOR: &[u8] = b"aafp-v1-handshake";

/// Domain separator for Session ID derivation (RFC-0002 §5.7).
pub const SESSION_ID_INFO: &[u8] = b"aafp-session-id-v1";

/// Domain separator for DoS MAC key derivation (RFC-0002 §5.8).
pub const DOS_MAC_KEY_INFO: &[u8] = b"aafp-v1-dos-mac-key";

/// TLS exporter label for channel binding (RFC-0002 §2.5).
pub const TLS_EXPORTER_LABEL: &str = "EXPORTER-AAFP-Channel-Binding";

/// Nonce size: 32 bytes (RFC-0002 §5.3-5.4).
pub const NONCE_SIZE: usize = 32;

/// Session ID size: 32 bytes (RFC-0002 §5.7).
pub const SESSION_ID_SIZE: usize = 32;

/// AgentId size: 32 bytes (SHA-256 output).
pub const AGENT_ID_SIZE: usize = 32;

/// Key algorithm: ML-DSA-65 = 1 (RFC-0003 §2.3).
pub const KEY_ALG_ML_DSA_65: u64 = 1;

/// AAFP protocol version 1.
pub const PROTOCOL_VERSION: u64 = 1;

type HmacSha256 = Hmac<Sha256>;

/// Running transcript hash for the handshake.
#[derive(Clone, Debug)]
pub struct TranscriptHash {
    state: Sha256,
    /// The current hash value (updated after each fold).
    current: [u8; 32],
}

impl TranscriptHash {
    /// Initialize with TLS channel binding value (RFC-0002 §5.6 Step 1).
    pub fn from_tls_binding(tls_binding: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(tls_binding);
        let current = hasher.finalize_reset().into();
        Self {
            state: hasher,
            current,
        }
    }

    /// Fold a CBOR-encoded message into the transcript hash.
    /// Returns the new hash value after folding.
    pub fn fold(&mut self, cbor_bytes: &[u8]) -> [u8; 32] {
        // h = SHA-256(h || cbor_bytes)
        self.state.update(self.current);
        self.state.update(cbor_bytes);
        self.current = self.state.finalize_reset().into();
        self.current
    }

    /// Get the current transcript hash value.
    pub fn current(&self) -> &[u8; 32] {
        &self.current
    }
}

/// ClientHello message (RFC-0002 §5.3).
///
/// CBOR structure (integer keys):
/// ```cbor
/// ClientHello = {
///     1: uint,       // protocol_version
///     2: bstr,       // agent_id (32 bytes)
///     3: bstr,       // public_key (1952 bytes)
///     4: bstr,       // nonce (32 bytes)
///     5: [ *CapabilityDescriptor ],  // capabilities
///     6: [ *ExtensionEntry ],        // extensions
///     7: bstr,       // signature
///     8: uint,       // expires_at
///     9: bstr,       // receiver_mac (optional DoS MAC; MUST be omitted when absent, NOT null — A-2)
///     10: uint,      // key_algorithm
/// }
/// ```
#[derive(Clone, Debug)]
pub struct ClientHello {
    /// Protocol version (must equal `PROTOCOL_VERSION`).
    pub protocol_version: u64,
    /// Agent identifier (SHA-256 of the public key, 32 bytes).
    pub agent_id: Vec<u8>,
    /// ML-DSA-65 public key (1952 bytes).
    pub public_key: Vec<u8>,
    /// Random 32-byte nonce.
    pub nonce: [u8; NONCE_SIZE],
    /// Capability descriptors advertised by the client.
    pub capabilities: Vec<Value>,
    /// Extension entries advertised by the client.
    pub extensions: Vec<Value>,
    /// ML-DSA-65 signature over the transcript hash.
    pub signature: Vec<u8>,
    /// Expiry timestamp (unix seconds); the identity must not be expired.
    pub expires_at: u64,
    /// Optional DoS receiver MAC (omitted when absent per A-2).
    pub receiver_mac: Option<Vec<u8>>,
    /// Key algorithm identifier (must equal `KEY_ALG_ML_DSA_65`).
    pub key_algorithm: u64,
}

impl ClientHello {
    /// Encode to canonical CBOR, excluding the signature (key 7) and receiver_mac (key 9).
    /// This is the signature input per RFC-0002 §5.6.
    pub fn to_cbor_without_sig_and_mac(&self) -> Value {
        let entries: Vec<(i64, Value)> = vec![
            (1, Value::Unsigned(self.protocol_version)),
            (2, Value::ByteString(self.agent_id.clone())),
            (3, Value::ByteString(self.public_key.clone())),
            (4, Value::ByteString(self.nonce.to_vec())),
            (5, Value::Array(self.capabilities.clone())),
            (6, Value::Array(self.extensions.clone())),
            (8, Value::Unsigned(self.expires_at)),
            (10, Value::Unsigned(self.key_algorithm)),
        ];
        // Sort not needed — encode() handles canonical sorting
        int_map(entries)
    }

    /// Encode to canonical CBOR with all fields (including signature and receiver_mac).
    ///
    /// Per A-2 (Rev 6): optional fields MUST be omitted when absent, NOT
    /// encoded as `null`. This ensures deterministic signature bytes.
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = vec![
            (1, Value::Unsigned(self.protocol_version)),
            (2, Value::ByteString(self.agent_id.clone())),
            (3, Value::ByteString(self.public_key.clone())),
            (4, Value::ByteString(self.nonce.to_vec())),
            (5, Value::Array(self.capabilities.clone())),
            (6, Value::Array(self.extensions.clone())),
            (7, Value::ByteString(self.signature.clone())),
            (8, Value::Unsigned(self.expires_at)),
            (10, Value::Unsigned(self.key_algorithm)),
        ];
        // A-2: Omit receiver_mac when absent (NOT null)
        if let Some(mac) = &self.receiver_mac {
            entries.push((9, Value::ByteString(mac.clone())));
        }
        int_map(entries)
    }

    /// Decode from a CBOR Value.
    pub fn from_cbor(val: &Value) -> Result<Self, HandshakeError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        Ok(Self {
            protocol_version: expect_u64(get(1), "protocol_version")?,
            agent_id: expect_bstr(get(2), "agent_id")?,
            public_key: expect_bstr(get(3), "public_key")?,
            nonce: expect_bstr_32(get(4), "nonce")?,
            capabilities: expect_array(get(5), "capabilities")?,
            extensions: expect_array(get(6), "extensions")?,
            signature: expect_bstr(get(7), "signature")?,
            expires_at: expect_u64(get(8), "expires_at")?,
            receiver_mac: match get(9) {
                None => None,
                Some(Value::ByteString(b)) => Some(b.clone()),
                // A-2 (Rev 6): null is no longer a valid encoding for
                // optional fields. The field MUST be omitted when absent.
                Some(Value::Null) => {
                    return Err(HandshakeError::InvalidField {
                        field: "receiver_mac",
                        message:
                            "null encoding is not valid; field must be omitted when absent (A-2)"
                                .to_string(),
                    })
                }
                Some(other) => {
                    return Err(HandshakeError::InvalidField {
                        field: "receiver_mac",
                        message: format!("expected bstr, got {:?}", other),
                    })
                }
            },
            key_algorithm: expect_u64(get(10), "key_algorithm")?,
        })
    }
}

/// ServerHello message (RFC-0002 §5.4).
#[derive(Clone, Debug)]
pub struct ServerHello {
    /// Protocol version (must equal `PROTOCOL_VERSION`).
    pub protocol_version: u64,
    /// Agent identifier (SHA-256 of the public key, 32 bytes).
    pub agent_id: Vec<u8>,
    /// ML-DSA-65 public key (1952 bytes).
    pub public_key: Vec<u8>,
    /// Random 32-byte nonce.
    pub nonce: [u8; NONCE_SIZE],
    /// Capability descriptors advertised by the server.
    pub capabilities: Vec<Value>,
    /// Extension entries advertised by the server.
    pub extensions: Vec<Value>,
    /// Session identifier derived from the handshake transcript (32 bytes).
    pub session_id: [u8; SESSION_ID_SIZE],
    /// ML-DSA-65 signature over the transcript hash.
    pub signature: Vec<u8>,
    /// Expiry timestamp (unix seconds); the identity must not be expired.
    pub expires_at: u64,
    /// Key algorithm identifier (must equal `KEY_ALG_ML_DSA_65`).
    pub key_algorithm: u64,
}

impl ServerHello {
    /// Encode to canonical CBOR, excluding the signature (key 8).
    pub fn to_cbor_without_sig(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(self.protocol_version)),
            (2, Value::ByteString(self.agent_id.clone())),
            (3, Value::ByteString(self.public_key.clone())),
            (4, Value::ByteString(self.nonce.to_vec())),
            (5, Value::Array(self.capabilities.clone())),
            (6, Value::Array(self.extensions.clone())),
            (7, Value::ByteString(self.session_id.to_vec())),
            (9, Value::Unsigned(self.expires_at)),
            (10, Value::Unsigned(self.key_algorithm)),
        ])
    }

    /// Encode to canonical CBOR with all fields.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(self.protocol_version)),
            (2, Value::ByteString(self.agent_id.clone())),
            (3, Value::ByteString(self.public_key.clone())),
            (4, Value::ByteString(self.nonce.to_vec())),
            (5, Value::Array(self.capabilities.clone())),
            (6, Value::Array(self.extensions.clone())),
            (7, Value::ByteString(self.session_id.to_vec())),
            (8, Value::ByteString(self.signature.clone())),
            (9, Value::Unsigned(self.expires_at)),
            (10, Value::Unsigned(self.key_algorithm)),
        ])
    }

    /// Decode from a CBOR Value.
    pub fn from_cbor(val: &Value) -> Result<Self, HandshakeError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        Ok(Self {
            protocol_version: expect_u64(get(1), "protocol_version")?,
            agent_id: expect_bstr(get(2), "agent_id")?,
            public_key: expect_bstr(get(3), "public_key")?,
            nonce: expect_bstr_32(get(4), "nonce")?,
            capabilities: expect_array(get(5), "capabilities")?,
            extensions: expect_array(get(6), "extensions")?,
            session_id: expect_bstr_32(get(7), "session_id")?,
            signature: expect_bstr(get(8), "signature")?,
            expires_at: expect_u64(get(9), "expires_at")?,
            key_algorithm: expect_u64(get(10), "key_algorithm")?,
        })
    }
}

/// ClientFinished message (RFC-0002 §5.5).
#[derive(Clone, Debug)]
pub struct ClientFinished {
    /// Session identifier matching the one from ServerHello.
    pub session_id: [u8; SESSION_ID_SIZE],
    /// ML-DSA-65 signature over the transcript hash.
    pub signature: Vec<u8>,
}

impl ClientFinished {
    /// Encode to canonical CBOR, excluding the signature (key 2).
    pub fn to_cbor_without_sig(&self) -> Value {
        int_map(vec![(1, Value::ByteString(self.session_id.to_vec()))])
    }

    /// Encode to canonical CBOR with all fields.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::ByteString(self.session_id.to_vec())),
            (2, Value::ByteString(self.signature.clone())),
        ])
    }

    /// Decode from a CBOR Value.
    pub fn from_cbor(val: &Value) -> Result<Self, HandshakeError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        Ok(Self {
            session_id: expect_bstr_32(get(1), "session_id")?,
            signature: expect_bstr(get(2), "signature")?,
        })
    }
}

/// Compute the signature input: domain_separator || transcript_hash.
fn signature_input(h: &[u8; 32]) -> Vec<u8> {
    let mut input = Vec::with_capacity(DOMAIN_SEPARATOR.len() + 32);
    input.extend_from_slice(DOMAIN_SEPARATOR);
    input.extend_from_slice(h);
    input
}

/// Derive Session ID (RFC-0002 §5.7, Rev 6 A-4).
///
/// ```text
/// ikm = h_after_clienthello || server_agent_id
/// prk = HKDF-Extract(salt = client_nonce || server_nonce, IKM = ikm)
/// session_id = HKDF-Expand(prk, info = "aafp-session-id-v1", L = 32)
/// ```
///
/// Per A-4 (Rev 6): the session ID is bound to the server's AgentId to
/// prevent session fixation. The server_agent_id is appended to the
/// transcript hash as IKM input.
pub fn derive_session_id(
    h_after_clienthello: &[u8; 32],
    client_nonce: &[u8; NONCE_SIZE],
    server_nonce: &[u8; NONCE_SIZE],
    server_agent_id: &[u8],
) -> [u8; SESSION_ID_SIZE] {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);

    // A-4: Bind session ID to server identity
    let mut ikm = Vec::with_capacity(32 + server_agent_id.len());
    ikm.extend_from_slice(h_after_clienthello);
    ikm.extend_from_slice(server_agent_id);

    let prk = hkdf_sha256(&salt, &ikm, SESSION_ID_INFO, SESSION_ID_SIZE);
    let mut session_id = [0u8; SESSION_ID_SIZE];
    session_id.copy_from_slice(&prk);
    session_id
}

/// Compute DoS receiver MAC (RFC-0002 §5.8).
pub fn compute_receiver_mac(receiver_agent_id: &[u8], ch_cbor_bytes: &[u8]) -> Vec<u8> {
    let mac_key = hkdf_sha256(&[], receiver_agent_id, DOS_MAC_KEY_INFO, 32);
    let mut hmac = HmacSha256::new_from_slice(&mac_key).expect("HMAC key length");
    hmac.update(ch_cbor_bytes);
    hmac.finalize().into_bytes().to_vec()
}

/// Verify DoS receiver MAC (RFC-0002 §5.8).
pub fn verify_receiver_mac(
    receiver_agent_id: &[u8],
    ch_cbor_bytes: &[u8],
    expected_mac: &[u8],
) -> bool {
    let computed = compute_receiver_mac(receiver_agent_id, ch_cbor_bytes);
    // Constant-time comparison
    if computed.len() != expected_mac.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(expected_mac.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Generate a random 32-byte nonce.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    use rand::RngCore;
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Handshake errors.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// A field had an invalid value or type.
    #[error("invalid field '{field}': {message}")]
    InvalidField {
        /// Name of the invalid field.
        field: &'static str,
        /// Description of why the field is invalid.
        message: String,
    },
    /// A required field was missing from the CBOR map.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// A CBOR encoding/decoding error occurred.
    #[error("CBOR error: {0}")]
    Cbor(#[from] aafp_cbor::CborError),
    /// Signature verification over the transcript failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    /// The session ID did not match the expected value.
    #[error("session ID mismatch")]
    SessionIdMismatch,
    /// Protocol version does not match the expected value.
    #[error("protocol version mismatch: expected {expected}, got {got}")]
    VersionMismatch {
        /// Expected protocol version.
        expected: u64,
        /// Received protocol version.
        got: u64,
    },
    /// The agent ID does not equal SHA-256(public_key).
    #[error("agent ID does not match SHA-256(public_key)")]
    InvalidAgentId,
    /// The identity has expired (expires_at <= now).
    #[error("identity expired: expires_at={expires_at}, now={now}")]
    IdentityExpired {
        /// Expiry timestamp of the identity.
        expires_at: u64,
        /// Current time when the check was performed.
        now: u64,
    },
    /// The key algorithm is not supported.
    #[error("unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(u64),
}

// Helper functions for CBOR field extraction

fn expect_u64(val: Option<&Value>, field: &'static str) -> Result<u64, HandshakeError> {
    match val {
        Some(Value::Unsigned(n)) => Ok(*n),
        Some(other) => Err(HandshakeError::InvalidField {
            field,
            message: format!("expected uint, got {:?}", other),
        }),
        None => Err(HandshakeError::MissingField(field)),
    }
}

fn expect_bstr(val: Option<&Value>, field: &'static str) -> Result<Vec<u8>, HandshakeError> {
    match val {
        Some(Value::ByteString(b)) => Ok(b.clone()),
        Some(other) => Err(HandshakeError::InvalidField {
            field,
            message: format!("expected bstr, got {:?}", other),
        }),
        None => Err(HandshakeError::MissingField(field)),
    }
}

fn expect_bstr_32(val: Option<&Value>, field: &'static str) -> Result<[u8; 32], HandshakeError> {
    let b = expect_bstr(val, field)?;
    if b.len() != 32 {
        return Err(HandshakeError::InvalidField {
            field,
            message: format!("expected 32 bytes, got {}", b.len()),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Ok(arr)
}

fn expect_array(val: Option<&Value>, field: &'static str) -> Result<Vec<Value>, HandshakeError> {
    match val {
        Some(Value::Array(arr)) => Ok(arr.clone()),
        Some(other) => Err(HandshakeError::InvalidField {
            field,
            message: format!("expected array, got {:?}", other),
        }),
        None => Err(HandshakeError::MissingField(field)),
    }
}

// --- Handshake message verification ---

/// Verify the agent_id ↔ public_key invariant for a hello message.
///
/// This is the single invariant that protects every higher layer:
///   claimed AgentId == SHA-256(public_key)
///
/// Returns the verified AgentId as a fixed-size array on success.
fn verify_agent_id_binding(
    agent_id: &[u8],
    public_key: &[u8],
) -> Result<[u8; AGENT_ID_SIZE], HandshakeError> {
    if agent_id.len() != AGENT_ID_SIZE {
        return Err(HandshakeError::InvalidField {
            field: "agent_id",
            message: format!("expected {} bytes, got {}", AGENT_ID_SIZE, agent_id.len()),
        });
    }
    let computed = Sha256::digest(public_key);
    if computed.as_slice() != agent_id {
        return Err(HandshakeError::InvalidAgentId);
    }
    let mut id = [0u8; AGENT_ID_SIZE];
    id.copy_from_slice(agent_id);
    Ok(id)
}

/// Verify a ClientHello message (RFC-0002 §5.3).
///
/// Checks (in order):
/// 1. protocol_version matches PROTOCOL_VERSION
/// 2. key_algorithm matches KEY_ALG_ML_DSA_65
/// 3. agent_id == SHA-256(public_key)  [the identity invariant]
/// 4. public_key is a valid ML-DSA-65 key
/// 5. signature verifies over (domain_separator || transcript_hash)
/// 6. expires_at is in the future
///
/// Returns the verified AgentId on success.
pub fn verify_client_hello(
    ch: &ClientHello,
    transcript_hash: &[u8; 32],
    now: u64,
) -> Result<[u8; AGENT_ID_SIZE], HandshakeError> {
    // 1. Protocol version
    if ch.protocol_version != PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            got: ch.protocol_version,
        });
    }

    // 2. Key algorithm
    if ch.key_algorithm != KEY_ALG_ML_DSA_65 {
        return Err(HandshakeError::UnsupportedAlgorithm(ch.key_algorithm));
    }

    // 3. AgentId ↔ public_key invariant
    let verified_agent_id = verify_agent_id_binding(&ch.agent_id, &ch.public_key)?;

    // 4. Public key validity
    let pk =
        MlDsa65PublicKey::from_bytes(&ch.public_key).map_err(|_| HandshakeError::InvalidField {
            field: "public_key",
            message: "invalid ML-DSA-65 public key".into(),
        })?;

    // 5. Signature verification
    let sig =
        MlDsa65Signature::from_bytes(&ch.signature).map_err(|_| HandshakeError::InvalidField {
            field: "signature",
            message: format!("expected {} bytes", crate::dsa::ML_DSA_65_SIGNATURE_LEN),
        })?;
    let sig_input = signature_input(transcript_hash);
    if !MlDsa65::verify(&pk, &sig_input, &sig) {
        return Err(HandshakeError::SignatureVerificationFailed);
    }

    // 6. Expiry
    if ch.expires_at <= now {
        return Err(HandshakeError::IdentityExpired {
            expires_at: ch.expires_at,
            now,
        });
    }

    Ok(verified_agent_id)
}

/// Verify a ServerHello message (RFC-0002 §5.4).
///
/// Same checks as `verify_client_hello`, plus the session_id is returned
/// for the caller to use.
///
/// Returns (verified AgentId, session_id) on success.
pub fn verify_server_hello(
    sh: &ServerHello,
    transcript_hash: &[u8; 32],
    now: u64,
) -> Result<([u8; AGENT_ID_SIZE], [u8; SESSION_ID_SIZE]), HandshakeError> {
    // 1. Protocol version
    if sh.protocol_version != PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            got: sh.protocol_version,
        });
    }

    // 2. Key algorithm
    if sh.key_algorithm != KEY_ALG_ML_DSA_65 {
        return Err(HandshakeError::UnsupportedAlgorithm(sh.key_algorithm));
    }

    // 3. AgentId ↔ public_key invariant
    let verified_agent_id = verify_agent_id_binding(&sh.agent_id, &sh.public_key)?;

    // 4. Public key validity
    let pk =
        MlDsa65PublicKey::from_bytes(&sh.public_key).map_err(|_| HandshakeError::InvalidField {
            field: "public_key",
            message: "invalid ML-DSA-65 public key".into(),
        })?;

    // 5. Signature verification
    let sig =
        MlDsa65Signature::from_bytes(&sh.signature).map_err(|_| HandshakeError::InvalidField {
            field: "signature",
            message: format!("expected {} bytes", crate::dsa::ML_DSA_65_SIGNATURE_LEN),
        })?;
    let sig_input = signature_input(transcript_hash);
    if !MlDsa65::verify(&pk, &sig_input, &sig) {
        return Err(HandshakeError::SignatureVerificationFailed);
    }

    // 6. Expiry
    if sh.expires_at <= now {
        return Err(HandshakeError::IdentityExpired {
            expires_at: sh.expires_at,
            now,
        });
    }

    Ok((verified_agent_id, sh.session_id))
}

/// Verify a ClientFinished message (RFC-0002 §5.5).
///
/// Checks that the signature verifies against the client's public key
/// (from the previously-verified ClientHello) over the transcript hash.
pub fn verify_client_finished(
    cf: &ClientFinished,
    transcript_hash: &[u8; 32],
    client_public_key: &[u8],
    expected_session_id: &[u8; SESSION_ID_SIZE],
) -> Result<(), HandshakeError> {
    // 1. Session ID must match the one derived from the handshake
    if cf.session_id != *expected_session_id {
        return Err(HandshakeError::SessionIdMismatch);
    }

    // 2. Signature verification
    let pk = MlDsa65PublicKey::from_bytes(client_public_key).map_err(|_| {
        HandshakeError::InvalidField {
            field: "client_public_key",
            message: "invalid ML-DSA-65 public key".into(),
        }
    })?;
    let sig =
        MlDsa65Signature::from_bytes(&cf.signature).map_err(|_| HandshakeError::InvalidField {
            field: "signature",
            message: format!("expected {} bytes", crate::dsa::ML_DSA_65_SIGNATURE_LEN),
        })?;
    let sig_input = signature_input(transcript_hash);
    if !MlDsa65::verify(&pk, &sig_input, &sig) {
        return Err(HandshakeError::SignatureVerificationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::MlDsa65SecretKey;
    use crate::traits::SignatureScheme;
    use sha2::Digest;

    #[test]
    fn test_transcript_hash_initialization() {
        let tls_binding = [0x42u8; 32];
        let th = TranscriptHash::from_tls_binding(&tls_binding);
        // h = SHA-256(tls_binding)
        let expected = Sha256::digest(&tls_binding);
        assert_eq!(th.current(), expected.as_slice());
    }

    #[test]
    fn test_transcript_hash_fold() {
        let tls_binding = [0x42u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);

        let cbor_bytes = vec![0xA1, 0x01, 0x02]; // Some CBOR
        th.fold(&cbor_bytes);

        // h = SHA-256(SHA-256(tls_binding) || cbor_bytes)
        let h1 = Sha256::digest(&tls_binding);
        let mut hasher = Sha256::new();
        hasher.update(h1);
        hasher.update(&cbor_bytes);
        let expected = hasher.finalize();
        assert_eq!(th.current(), expected.as_slice());
    }

    #[test]
    fn test_session_id_derivation() {
        let h = [0x11u8; 32];
        let client_nonce = [0x22u8; 32];
        let server_nonce = [0x33u8; 32];

        let sid = derive_session_id(&h, &client_nonce, &server_nonce, &[0xAAu8; 32]);
        assert_eq!(sid.len(), SESSION_ID_SIZE);

        // Same inputs → same output
        let sid2 = derive_session_id(&h, &client_nonce, &server_nonce, &[0xAAu8; 32]);
        assert_eq!(sid, sid2);

        // Different nonces → different output
        let sid3 = derive_session_id(&h, &client_nonce, &[0x44u8; 32], &[0xAAu8; 32]);
        assert_ne!(sid, sid3);
    }

    #[test]
    fn test_receiver_mac() {
        let agent_id = [0xAAu8; 32];
        let ch_bytes = vec![0x01, 0x02, 0x03, 0x04];

        let mac = compute_receiver_mac(&agent_id, &ch_bytes);
        assert_eq!(mac.len(), 32); // HMAC-SHA256 output

        // Valid MAC
        assert!(verify_receiver_mac(&agent_id, &ch_bytes, &mac));

        // Wrong agent_id
        assert!(!verify_receiver_mac(&[0xBBu8; 32], &ch_bytes, &mac));

        // Wrong data
        assert!(!verify_receiver_mac(&agent_id, &[0xFF, 0xFF], &mac));
    }

    #[test]
    fn test_client_hello_cbor_roundtrip() {
        let ch = ClientHello {
            protocol_version: 1,
            agent_id: vec![0x11u8; 32],
            public_key: vec![0x22u8; 1952],
            nonce: [0x33u8; 32],
            capabilities: vec![],
            extensions: vec![],
            signature: vec![0x44u8; 3309],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: 1,
        };

        let cbor = ch.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let ch2 = ClientHello::from_cbor(&decoded).unwrap();

        assert_eq!(ch2.protocol_version, ch.protocol_version);
        assert_eq!(ch2.agent_id, ch.agent_id);
        assert_eq!(ch2.public_key, ch.public_key);
        assert_eq!(ch2.nonce, ch.nonce);
        assert_eq!(ch2.signature, ch.signature);
        assert_eq!(ch2.expires_at, ch.expires_at);
        assert_eq!(ch2.key_algorithm, ch.key_algorithm);
        assert_eq!(ch2.receiver_mac, None);
    }

    #[test]
    fn test_client_hello_without_sig_and_mac() {
        let ch = ClientHello {
            protocol_version: 1,
            agent_id: vec![0x11u8; 32],
            public_key: vec![0x22u8; 1952],
            nonce: [0x33u8; 32],
            capabilities: vec![],
            extensions: vec![],
            signature: vec![0x44u8; 3309],
            expires_at: 1700000000,
            receiver_mac: Some(vec![0x55u8; 32]),
            key_algorithm: 1,
        };

        let cbor = ch.to_cbor_without_sig_and_mac();
        // Should NOT have keys 7 (signature) or 9 (receiver_mac)
        assert!(aafp_cbor::int_map_get(&cbor, 7).is_none());
        assert!(aafp_cbor::int_map_get(&cbor, 9).is_none());
        // Should have keys 1, 2, 3, 4, 5, 6, 8, 10
        assert!(aafp_cbor::int_map_get(&cbor, 1).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 2).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 3).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 4).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 5).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 6).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 8).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 10).is_some());
    }

    #[test]
    fn test_server_hello_cbor_roundtrip() {
        let sh = ServerHello {
            protocol_version: 1,
            agent_id: vec![0xAAu8; 32],
            public_key: vec![0xBBu8; 1952],
            nonce: [0xCCu8; 32],
            capabilities: vec![],
            extensions: vec![],
            session_id: [0xDDu8; 32],
            signature: vec![0xEEu8; 3309],
            expires_at: 1700000000,
            key_algorithm: 1,
        };

        let cbor = sh.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let sh2 = ServerHello::from_cbor(&decoded).unwrap();

        assert_eq!(sh2.protocol_version, sh.protocol_version);
        assert_eq!(sh2.agent_id, sh.agent_id);
        assert_eq!(sh2.public_key, sh.public_key);
        assert_eq!(sh2.nonce, sh.nonce);
        assert_eq!(sh2.session_id, sh.session_id);
        assert_eq!(sh2.signature, sh.signature);
        assert_eq!(sh2.expires_at, sh.expires_at);
        assert_eq!(sh2.key_algorithm, sh.key_algorithm);
    }

    #[test]
    fn test_server_hello_without_sig() {
        let sh = ServerHello {
            protocol_version: 1,
            agent_id: vec![0xAAu8; 32],
            public_key: vec![0xBBu8; 1952],
            nonce: [0xCCu8; 32],
            capabilities: vec![],
            extensions: vec![],
            session_id: [0xDDu8; 32],
            signature: vec![0xEEu8; 3309],
            expires_at: 1700000000,
            key_algorithm: 1,
        };

        let cbor = sh.to_cbor_without_sig();
        // Should NOT have key 8 (signature)
        assert!(aafp_cbor::int_map_get(&cbor, 8).is_none());
        // Should have key 7 (session_id)
        assert!(aafp_cbor::int_map_get(&cbor, 7).is_some());
    }

    #[test]
    fn test_client_finished_cbor_roundtrip() {
        let cf = ClientFinished {
            session_id: [0x11u8; 32],
            signature: vec![0x22u8; 3309],
        };

        let cbor = cf.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let cf2 = ClientFinished::from_cbor(&decoded).unwrap();

        assert_eq!(cf2.session_id, cf.session_id);
        assert_eq!(cf2.signature, cf.signature);
    }

    #[test]
    fn test_full_handshake_signatures() {
        // Generate keypairs
        let (client_pk, client_sk) = MlDsa65::keypair();
        let (server_pk, server_sk) = MlDsa65::keypair();

        // Compute agent IDs
        let client_agent_id = Sha256::digest(&client_pk.0).to_vec();
        let server_agent_id = Sha256::digest(&server_pk.0).to_vec();

        // TLS binding (would come from TLS exporter in real implementation)
        let tls_binding = [0x42u8; 32];

        // === Client side: construct and sign ClientHello ===
        let client_nonce = generate_nonce();
        let mut th_client = TranscriptHash::from_tls_binding(&tls_binding);

        let mut ch = ClientHello {
            protocol_version: PROTOCOL_VERSION,
            agent_id: client_agent_id.clone(),
            public_key: client_pk.0.clone(),
            nonce: client_nonce,
            capabilities: vec![],
            extensions: vec![],
            signature: vec![], // Will be filled in
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        // Step 2: Fold ClientHello CBOR (without sig and mac) into transcript
        let ch_cbor = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
        let h_after_ch = th_client.fold(&ch_cbor_bytes);

        // Sign
        let sig_input = signature_input(&h_after_ch);
        let ch_sig = MlDsa65::sign(&client_sk, &sig_input);
        ch.signature = ch_sig.0.clone();

        // === Server side: receive and verify ClientHello ===
        let mut th_server = TranscriptHash::from_tls_binding(&tls_binding);

        // Reconstruct CH CBOR without sig and mac
        let ch_cbor_verify = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_verify_bytes = aafp_cbor::encode(&ch_cbor_verify).unwrap();
        assert_eq!(ch_cbor_verify_bytes, ch_cbor_bytes); // Must be identical

        let h_after_ch_server = th_server.fold(&ch_cbor_verify_bytes);
        assert_eq!(h_after_ch_server, h_after_ch); // Both sides must have same hash

        // Verify signature
        let sig_input_server = signature_input(&h_after_ch_server);
        let ch_sig_obj = MlDsa65Signature(ch.signature.clone());
        assert!(MlDsa65::verify(&client_pk, &sig_input_server, &ch_sig_obj));

        // === Server side: construct and sign ServerHello ===
        let server_nonce = generate_nonce();
        let session_id =
            derive_session_id(&h_after_ch, &client_nonce, &server_nonce, &server_agent_id);

        let mut sh = ServerHello {
            protocol_version: PROTOCOL_VERSION,
            agent_id: server_agent_id.clone(),
            public_key: server_pk.0.clone(),
            nonce: server_nonce,
            capabilities: vec![],
            extensions: vec![],
            session_id,
            signature: vec![], // Will be filled in
            expires_at: 1700000000,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        // Step 3: Fold ServerHello CBOR (without sig) into transcript
        let sh_cbor = sh.to_cbor_without_sig();
        let sh_cbor_bytes = aafp_cbor::encode(&sh_cbor).unwrap();
        let h_after_sh = th_server.fold(&sh_cbor_bytes);

        // Sign
        let sh_sig_input = signature_input(&h_after_sh);
        let sh_sig = MlDsa65::sign(&server_sk, &sh_sig_input);
        sh.signature = sh_sig.0.clone();

        // === Client side: receive and verify ServerHello ===
        let sh_cbor_verify = sh.to_cbor_without_sig();
        let sh_cbor_verify_bytes = aafp_cbor::encode(&sh_cbor_verify).unwrap();
        assert_eq!(sh_cbor_verify_bytes, sh_cbor_bytes);

        let h_after_sh_client = th_client.fold(&sh_cbor_verify_bytes);
        assert_eq!(h_after_sh_client, h_after_sh);

        // Verify signature
        let sh_sig_input_client = signature_input(&h_after_sh_client);
        let sh_sig_obj = MlDsa65Signature(sh.signature.clone());
        assert!(MlDsa65::verify(
            &server_pk,
            &sh_sig_input_client,
            &sh_sig_obj
        ));

        // Verify session ID
        let expected_sid =
            derive_session_id(&h_after_ch, &client_nonce, &server_nonce, &server_agent_id);
        assert_eq!(sh.session_id, expected_sid);

        // === Client side: construct and sign ClientFinished ===
        let mut cf = ClientFinished {
            session_id: sh.session_id,
            signature: vec![],
        };

        let cf_cbor = cf.to_cbor_without_sig();
        let cf_cbor_bytes = aafp_cbor::encode(&cf_cbor).unwrap();
        let h_after_cf = th_client.fold(&cf_cbor_bytes);

        let cf_sig_input = signature_input(&h_after_cf);
        let cf_sig = MlDsa65::sign(&client_sk, &cf_sig_input);
        cf.signature = cf_sig.0.clone();

        // === Server side: receive and verify ClientFinished ===
        let cf_cbor_verify = cf.to_cbor_without_sig();
        let cf_cbor_verify_bytes = aafp_cbor::encode(&cf_cbor_verify).unwrap();
        assert_eq!(cf_cbor_verify_bytes, cf_cbor_bytes);

        let h_after_cf_server = th_server.fold(&cf_cbor_verify_bytes);
        assert_eq!(h_after_cf_server, h_after_cf);

        // Verify signature
        let cf_sig_input_server = signature_input(&h_after_cf_server);
        let cf_sig_obj = MlDsa65Signature(cf.signature.clone());
        assert!(MlDsa65::verify(
            &client_pk,
            &cf_sig_input_server,
            &cf_sig_obj
        ));

        // Both sides now have the same final transcript hash
        assert_eq!(th_client.current(), th_server.current());
    }

    #[test]
    fn test_canonical_encoding_deterministic_for_signatures() {
        // The same ClientHello must always produce the same CBOR bytes
        let ch = ClientHello {
            protocol_version: 1,
            agent_id: vec![0x11u8; 32],
            public_key: vec![0x22u8; 1952],
            nonce: [0x33u8; 32],
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: 1,
        };

        let cbor1 = ch.to_cbor_without_sig_and_mac();
        let cbor2 = ch.to_cbor_without_sig_and_mac();
        let bytes1 = aafp_cbor::encode(&cbor1).unwrap();
        let bytes2 = aafp_cbor::encode(&cbor2).unwrap();
        assert_eq!(bytes1, bytes2, "CBOR encoding must be deterministic");
    }

    // --- Tests for verify_client_hello / verify_server_hello / verify_client_finished ---

    /// Build a valid ClientHello with correct agent_id ↔ public_key binding.
    fn build_valid_client_hello() -> (ClientHello, MlDsa65SecretKey, [u8; 32]) {
        let (pk, sk) = MlDsa65::keypair();
        let agent_id = Sha256::digest(&pk.0).to_vec();
        let tls_binding = [0x42u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);

        let mut ch = ClientHello {
            protocol_version: PROTOCOL_VERSION,
            agent_id,
            public_key: pk.0.clone(),
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
        let h_after_ch = th.fold(&ch_cbor_bytes);

        let sig_input = signature_input(&h_after_ch);
        let sig = MlDsa65::sign(&sk, &sig_input);
        ch.signature = sig.0;

        (ch, sk, h_after_ch)
    }

    #[test]
    fn test_verify_client_hello_valid() {
        let (ch, _sk, h_after_ch) = build_valid_client_hello();
        let agent_id = verify_client_hello(&ch, &h_after_ch, 0).unwrap();
        assert_eq!(agent_id.as_slice(), ch.agent_id);
    }

    #[test]
    fn test_verify_client_hello_rejects_mismatched_agent_id() {
        let (mut ch, _sk, h_after_ch) = build_valid_client_hello();
        // Tamper with agent_id — this breaks the SHA-256(public_key) binding
        ch.agent_id[0] ^= 0xff;
        let err = verify_client_hello(&ch, &h_after_ch, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidAgentId), "got {err:?}");
    }

    #[test]
    fn test_verify_client_hello_rejects_wrong_public_key() {
        let (mut ch, _sk, h_after_ch) = build_valid_client_hello();
        // Replace public_key with a different key — agent_id no longer matches
        let (pk2, _) = MlDsa65::keypair();
        ch.public_key = pk2.0.clone();
        let err = verify_client_hello(&ch, &h_after_ch, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidAgentId), "got {err:?}");
    }

    #[test]
    fn test_verify_client_hello_rejects_bad_signature() {
        let (mut ch, _sk, h_after_ch) = build_valid_client_hello();
        // Tamper with signature
        ch.signature[0] ^= 0xff;
        let err = verify_client_hello(&ch, &h_after_ch, 0).unwrap_err();
        assert!(
            matches!(err, HandshakeError::SignatureVerificationFailed),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_client_hello_rejects_version_mismatch() {
        let (mut ch, _sk, h_after_ch) = build_valid_client_hello();
        ch.protocol_version = 99;
        let err = verify_client_hello(&ch, &h_after_ch, 0).unwrap_err();
        assert!(
            matches!(err, HandshakeError::VersionMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_client_hello_rejects_expired() {
        let (ch, _sk, h_after_ch) = build_valid_client_hello();
        // expires_at=1700000000, so now=1700000001 should reject
        let err = verify_client_hello(&ch, &h_after_ch, 1700000001).unwrap_err();
        assert!(
            matches!(err, HandshakeError::IdentityExpired { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_client_hello_rejects_wrong_key_algorithm() {
        let (mut ch, _sk, h_after_ch) = build_valid_client_hello();
        ch.key_algorithm = 99;
        let err = verify_client_hello(&ch, &h_after_ch, 0).unwrap_err();
        assert!(
            matches!(err, HandshakeError::UnsupportedAlgorithm(_)),
            "got {err:?}"
        );
    }

    /// Build a valid ServerHello with correct agent_id ↔ public_key binding.
    fn build_valid_server_hello() -> (
        ServerHello,
        MlDsa65SecretKey,
        [u8; 32],
        [u8; SESSION_ID_SIZE],
    ) {
        let (pk, sk) = MlDsa65::keypair();
        let agent_id = Sha256::digest(&pk.0).to_vec();
        let tls_binding = [0x42u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);

        // Need a ClientHello first to derive session_id
        let client_nonce = generate_nonce();
        let ch_cbor = ClientHello {
            protocol_version: PROTOCOL_VERSION,
            agent_id: vec![0xAA; 32],
            public_key: vec![0xBB; 1952],
            nonce: client_nonce,
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        }
        .to_cbor_without_sig_and_mac();
        let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
        let h_after_ch = th.fold(&ch_cbor_bytes);

        let server_nonce = generate_nonce();
        let session_id = derive_session_id(&h_after_ch, &client_nonce, &server_nonce, &agent_id);

        let mut sh = ServerHello {
            protocol_version: PROTOCOL_VERSION,
            agent_id,
            public_key: pk.0.clone(),
            nonce: server_nonce,
            capabilities: vec![],
            extensions: vec![],
            session_id,
            signature: vec![],
            expires_at: 1700000000,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        let sh_cbor = sh.to_cbor_without_sig();
        let sh_cbor_bytes = aafp_cbor::encode(&sh_cbor).unwrap();
        let h_after_sh = th.fold(&sh_cbor_bytes);

        let sig_input = signature_input(&h_after_sh);
        let sig = MlDsa65::sign(&sk, &sig_input);
        sh.signature = sig.0;

        (sh, sk, h_after_sh, session_id)
    }

    #[test]
    fn test_verify_server_hello_valid() {
        let (sh, _sk, h_after_sh, expected_sid) = build_valid_server_hello();
        let (agent_id, sid) = verify_server_hello(&sh, &h_after_sh, 0).unwrap();
        assert_eq!(agent_id.as_slice(), sh.agent_id);
        assert_eq!(sid, expected_sid);
    }

    #[test]
    fn test_verify_server_hello_rejects_mismatched_agent_id() {
        let (mut sh, _sk, h_after_sh, _) = build_valid_server_hello();
        sh.agent_id[0] ^= 0xff;
        let err = verify_server_hello(&sh, &h_after_sh, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidAgentId), "got {err:?}");
    }

    #[test]
    fn test_verify_server_hello_rejects_bad_signature() {
        let (mut sh, _sk, h_after_sh, _) = build_valid_server_hello();
        sh.signature[0] ^= 0xff;
        let err = verify_server_hello(&sh, &h_after_sh, 0).unwrap_err();
        assert!(
            matches!(err, HandshakeError::SignatureVerificationFailed),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_client_finished_valid() {
        let (pk, sk) = MlDsa65::keypair();
        let session_id = [0xCCu8; 32];
        let h = [0xDDu8; 32];

        let cf = ClientFinished {
            session_id,
            signature: MlDsa65::sign(&sk, &signature_input(&h)).0,
        };

        verify_client_finished(&cf, &h, &pk.0, &session_id).unwrap();
    }

    #[test]
    fn test_verify_client_finished_rejects_session_id_mismatch() {
        let (pk, sk) = MlDsa65::keypair();
        let h = [0xDDu8; 32];

        let cf = ClientFinished {
            session_id: [0xCCu8; 32],
            signature: MlDsa65::sign(&sk, &signature_input(&h)).0,
        };

        let err = verify_client_finished(&cf, &h, &pk.0, &[0xEEu8; 32]).unwrap_err();
        assert!(
            matches!(err, HandshakeError::SessionIdMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_client_finished_rejects_bad_signature() {
        let (pk, _sk) = MlDsa65::keypair();
        let session_id = [0xCCu8; 32];
        let h = [0xDDu8; 32];

        let mut cf = ClientFinished {
            session_id,
            signature: vec![0u8; crate::dsa::ML_DSA_65_SIGNATURE_LEN],
        };
        cf.signature[0] ^= 0xff;

        let err = verify_client_finished(&cf, &h, &pk.0, &session_id).unwrap_err();
        assert!(
            matches!(err, HandshakeError::SignatureVerificationFailed),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_client_hello_rejects_short_agent_id() {
        let (mut ch, _sk, h_after_ch) = build_valid_client_hello();
        ch.agent_id = vec![0xAA; 16]; // wrong length
        let err = verify_client_hello(&ch, &h_after_ch, 0).unwrap_err();
        assert!(
            matches!(
                err,
                HandshakeError::InvalidField {
                    field: "agent_id",
                    ..
                }
            ),
            "got {err:?}"
        );
    }
}
