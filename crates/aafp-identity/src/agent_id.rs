//! AgentID = SHA-256(ML-DSA-65 public key) = 32 bytes.
//!
//! Compact, collision-resistant, PQ-secure identifier for routing and DHT.
//! The full 1952-byte public key is exchanged once during the handshake and
//! cached; the 32-byte AgentID is used for all routing/discovery operations.

use sha2::{Digest, Sha256};

/// A 32-byte AgentID (SHA-256 of an ML-DSA-65 public key).
pub type AgentId = [u8; 32];

/// Derive an AgentID from an ML-DSA-65 public key.
pub fn derive_agent_id(public_key: &[u8]) -> AgentId {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Verify that a public key corresponds to an AgentID.
pub fn verify_agent_id(agent_id: &AgentId, public_key: &[u8]) -> bool {
    derive_agent_id(public_key) == *agent_id
}

/// Format an AgentID as a lowercase hex string.
pub fn agent_id_to_hex(agent_id: &AgentId) -> String {
    hex::encode(agent_id)
}

/// Parse an AgentID from a hex string.
pub fn agent_id_from_hex(hex_str: &str) -> Result<AgentId, &'static str> {
    let bytes = hex::decode(hex_str).map_err(|_| "invalid hex")?;
    if bytes.len() != 32 {
        return Err("agent ID must be 32 bytes (64 hex chars)");
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Truncate an AgentID to a short prefix for display (first 8 hex chars).
pub fn agent_id_short(agent_id: &AgentId) -> String {
    agent_id_to_hex(agent_id)[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_crypto::{MlDsa65, SignatureScheme};

    #[test]
    fn derive_and_verify() {
        let (pk, _sk) = MlDsa65::keypair();
        let id = derive_agent_id(&pk.0);
        assert_eq!(id.len(), 32);
        assert!(verify_agent_id(&id, &pk.0));
    }

    #[test]
    fn rejects_wrong_key() {
        let (pk1, _sk1) = MlDsa65::keypair();
        let (pk2, _sk2) = MlDsa65::keypair();
        let id1 = derive_agent_id(&pk1.0);
        assert!(!verify_agent_id(&id1, &pk2.0));
    }

    #[test]
    fn hex_roundtrip() {
        let id = [0xabu8; 32];
        let hex = agent_id_to_hex(&id);
        assert_eq!(hex.len(), 64);
        let decoded = agent_id_from_hex(&hex).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn hex_rejects_bad_input() {
        assert!(agent_id_from_hex("abc").is_err());
        assert!(agent_id_from_hex("zz").is_err());
    }

    #[test]
    fn different_keys_different_ids() {
        let (pk1, _) = MlDsa65::keypair();
        let (pk2, _) = MlDsa65::keypair();
        let id1 = derive_agent_id(&pk1.0);
        let id2 = derive_agent_id(&pk2.0);
        assert_ne!(id1, id2);
    }

    #[test]
    fn short_display() {
        let id = [0xabu8; 32];
        assert_eq!(agent_id_short(&id), "abababab");
    }
}
