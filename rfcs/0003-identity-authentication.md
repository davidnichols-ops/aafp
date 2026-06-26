# RFC-0003: AAFP Identity & Authentication

```
Status:         Draft
Number:         0003
Title:          Agent Identity, AgentRecord, Capability Descriptors,
                Authorization, and Session Lifecycle
Author:         AAFP Project
Created:        2025-06-25
Type:           Standards Track
Obsoletes:      —
Obsoleted by:   —
```

## 1. Overview

This RFC specifies the AAFP identity model: how agents are identified,
how their identities are authenticated, how capabilities are described,
how authorization is delegated, and how sessions are managed.

### 1.1 Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 2. Agent Identity

### 2.1 AgentId

An AgentId is a 32-byte identifier derived from an agent's ML-DSA-65
public key:

```
AgentId = SHA-256(ML-DSA-65 public key)
```

Properties:
- **Fixed 32 bytes**: Encoded as a CBOR byte string of length 32.
- **Quantum-safe**: SHA-256 is resistant to Shor's algorithm.
- **Collision-resistant**: 128-bit collision resistance.
- **Decoupled from key format**: If ML-DSA-65 is superseded by a
  future PQ signature scheme, AgentId derivation remains valid as
  long as the public key is hashable.

Implementations MUST verify that a received AgentId matches
`SHA-256(received_public_key)` during the handshake. If the
verification fails, the implementation MUST reject the handshake
with error code `2001` (invalid signature/identity).

### 2.2 AgentId Encoding

AgentIds are encoded as:

- **CBOR**: byte string (major type 2) of length 32
- **Hex**: 64-character lowercase hexadecimal string
- **Short form**: First 16 characters of the hex encoding, prefixed
  with `0x` (e.g., `0xa1b2c3d4e5f6a7b8`). Used for display only;
  NOT used for lookup or comparison.

### 2.3 ML-DSA-65 Key Pair

Each agent generates an ML-DSA-65 (FIPS 204) key pair:

- **Public key**: 1952 bytes
- **Secret key**: 4032 bytes
- **Signature**: 3309 bytes

The key pair is generated using the ML-DSA-65 key generation algorithm
as specified in FIPS 204. Implementations MUST use a cryptographically
secure random number generator for key generation.

### 2.4 Key Rotation

Agents MAY rotate their ML-DSA-65 key pair. Rotation produces a new
AgentId. The old AgentId and new AgentId have no cryptographic
relationship. Agents wishing to maintain identity across rotation
MUST use an out-of-band mechanism (e.g., a signed rotation statement
published to a directory service).

Key rotation is out of scope for AAFP v1. The protocol does not
provide an in-band key rotation mechanism.

## 3. AgentRecord

### 3.1 Purpose

An AgentRecord is a self-signed CBOR document that binds an AgentId
to its public key, capabilities, and network endpoints. It is the
primary identity advertisement in the network and is stored in the
discovery system (see RFC-0004).

### 3.2 CBOR Schema

```cbor
AgentRecord = {
    1: tstr,          // "record_type": "aafp-record-v1"
    2: bstr,          // "agent_id": 32-byte AgentId
    3: bstr,          // "public_key": ML-DSA-65 public key (1952 bytes)
    4: [ *CapabilityDescriptor ],  // "capabilities"
    5: [ *tstr ],     // "endpoints": multiaddrs
    6: uint,          // "created_at": Unix timestamp (seconds)
    7: uint,          // "expires_at": Unix timestamp (seconds)
    8: bstr,          // "signature": ML-DSA-65 signature
}
```

Fields are keyed by integers (not strings) for compact CBOR encoding.
The field key mapping is normative.

### 3.3 Field Semantics

| Key | Name | Type | Required | Description |
|-----|------|------|----------|-------------|
| 1 | record_type | tstr | Yes | MUST be `"aafp-record-v1"`. |
| 2 | agent_id | bstr(32) | Yes | SHA-256 of public_key. |
| 3 | public_key | bstr(1952) | Yes | ML-DSA-65 public key. |
| 4 | capabilities | array | Yes | CapabilityDescriptor array. May be empty. |
| 5 | endpoints | array | Yes | Multiaddr strings. May be empty. |
| 6 | created_at | uint | Yes | Unix timestamp when record was created. |
| 7 | expires_at | uint | Yes | Unix timestamp when record expires. |
| 8 | signature | bstr(3309) | Yes | ML-DSA-65 signature over the canonical CBOR encoding of fields 1–7. |

### 3.4 Signature Computation

The signature is computed as follows:

1. Construct a CBOR map containing fields 1 through 7 (excluding
   field 8, the signature).
2. Encode the map using canonical CBOR (see RFC-0002 Section 8).
3. Sign the resulting byte sequence using ML-DSA-65 with the agent's
   secret key.
4. Place the signature in field 8.

### 3.5 Verification

To verify an AgentRecord:

1. Decode the CBOR map.
2. Verify that `agent_id == SHA-256(public_key)`. If not, reject.
3. Extract fields 1–7 and re-encode using canonical CBOR.
4. Verify the ML-DSA-65 signature in field 8 against the re-encoded
   bytes using the public key in field 3.
5. Check that `expires_at > current_time`. If expired, reject.
6. Check that `record_type == "aafp-record-v1"`. If not, reject.

### 3.6 Forward Compatibility

Future versions of AgentRecord MAY add new fields with integer keys
≥ 9. Implementations MUST ignore unknown fields. Implementations
MUST NOT reject a record solely because it contains unknown fields.

Field types for existing keys MUST NOT change between versions.

## 4. CapabilityDescriptor

### 4.1 Purpose

A CapabilityDescriptor describes a single capability that an agent
provides. It separates the capability name (used for lookup) from
optional metadata (used for capability negotiation and filtering).

### 4.2 CBOR Schema

```cbor
CapabilityDescriptor = {
    1: tstr,                    // "name": capability name
    2: { *tstr => MetadataValue },  // "metadata": optional
}
```

### 4.3 MetadataValue

```cbor
MetadataValue = (
    bool /       // 0x01
    int /        // 0x02
    float /      // 0x03
    tstr /       // 0x04
    bstr         // 0x05
)
```

### 4.4 Field Semantics

| Key | Name | Type | Required | Description |
|-----|------|------|----------|-------------|
| 1 | name | tstr | Yes | Capability name (e.g., "inference", "translation"). |
| 2 | metadata | map | No | Optional metadata. May be absent or empty. |

### 4.5 Metadata Map

The metadata map uses `BTreeMap` ordering (lexicographic key ordering)
for deterministic serialization. This is critical for:

- **Signature verification**: AgentRecord signatures cover
  CapabilityDescriptors. Non-deterministic map ordering would break
  cross-implementation signature verification.
- **Caching**: Deterministic encoding enables byte-level comparison.

### 4.6 Why Typed Values Instead of Opaque Bytes

Metadata values are typed (`MetadataValue` enum) rather than opaque
`Vec<u8>` for the following reasons:

1. **Interoperability**: Typed values can be validated and interpreted
   by independent implementations without a secondary serialization
   layer.
2. **No nested encoding**: Opaque bytes require a secondary encoding
   (e.g., nested CBOR), complicating parsing and validation.
3. **Easier validation**: Typed values can be range-checked and
   type-checked at parse time.
4. **Deterministic serialization**: The typed enum maps directly to
   CBOR major types, ensuring canonical encoding.

### 4.7 Capability Names

Capability names are case-sensitive UTF-8 strings. Implementations
SHOULD use lowercase ASCII names with `-` separators (e.g.,
`inference`, `tool-calling`, `vision`).

A registry of well-known capability names MAY be established in a
future RFC. v1 does not define a registry; capability names are
application-defined.

### 4.8 Forward Compatibility

Future versions of CapabilityDescriptor MAY add new fields with
integer keys ≥ 3. The `MetadataValue` enum MAY add new variants.
Implementations MUST ignore unknown fields and MUST handle unknown
`MetadataValue` variants by skipping the containing metadata entry.

## 5. Authorization

### 5.1 AuthorizationProvider Trait

AAFP decouples authorization from the protocol via the
`AuthorizationProvider` trait. The protocol mandates the trait
interface, not any specific implementation.

```rust
pub trait AuthorizationProvider: Send + Sync {
    type Token: Serialize + DeserializeOwned;
    type Error;

    fn issue(
        &self,
        subject: &AgentId,
        capabilities: &[Capability],
        expires_at: u64,
    ) -> Result<Self::Token, Self::Error>;

    fn verify(
        &self,
        token: &Self::Token,
        subject: &AgentId,
    ) -> Result<Authorization, Self::Error>;
}
```

### 5.2 Authorization Result

```rust
pub struct Authorization {
    pub subject: AgentId,
    pub capabilities: Vec<Capability>,
    pub expires_at: u64,
    pub delegator: Option<AgentId>,
}
```

### 5.3 Capability

```rust
pub struct Capability {
    pub resource: String,
    pub action: String,
    pub constraints: Option<BTreeMap<String, MetadataValue>>,
}
```

### 5.4 UCAN Implementation

The first `AuthorizationProvider` implementation is UCAN (User-
Controlled Authorization Networks), a JWT-style capability delegation
model signed with ML-DSA-65.

UCAN tokens are CBOR-encoded (not JWT-encoded) for consistency with
the AAFP wire format. The CBOR schema:

```cbor
UcanToken = {
    1: bstr,          // "issuer": AgentId of the token issuer
    2: bstr,          // "subject": AgentId of the token subject
    3: [ *Capability ],  // "capabilities"
    4: uint,          // "expires_at": Unix timestamp
    5: bstr / null,   // "proof": parent token (for delegation chains)
    6: bstr,          // "signature": ML-DSA-65 signature
}
```

### 5.5 Delegation Chains

A UCAN token may reference a parent token (field 5, "proof"). This
forms a delegation chain:

```
Root Agent
    |
    | delegates to Agent B
    v
Agent B (token_1, proof=null)
    |
    | delegates to Agent C
    v
Agent C (token_2, proof=token_1)
```

Verification of a delegated token requires verifying the entire chain:

1. Verify the leaf token's signature.
2. If `proof` is present, verify the parent token recursively.
3. Verify that each token in the chain delegates a subset of the
   capabilities it was granted.
4. Verify that no token in the chain has expired.

### 5.6 Future Authorization Providers

The `AuthorizationProvider` trait allows future implementations
without protocol changes:

- **OIDC**: For enterprise deployments using existing identity
  providers.
- **PQ Capability Tokens**: For future PQ signature schemes beyond
  ML-DSA-65.
- **Custom systems**: For application-specific authorization models.

Implementations MAY support multiple `AuthorizationProvider`
implementations simultaneously. The handshake negotiates which
provider is in use (see RFC-0002 Section 5 and RFC-0006).

## 6. Session Lifecycle

### 6.1 Session States

```
   ┌──────────┐
   |  Initial  |
   └────┬─────┘
        | TLS handshake + ALPN negotiation
        v
   ┌──────────┐
   |Connecting|
   └────┬─────┘
        | AAFP handshake (ClientHello, ServerHello, ClientFinished)
        v
   ┌──────────┐
   |Established|
   └────┬─────┘
        | CLOSE frame or connection error
        v
   ┌──────────┐
   |  Closed   |
   └──────────┘
```

### 6.2 Session Properties

An established session has the following properties:

| Property | Description |
|----------|-------------|
| Session ID | Cryptographically unique identifier (see RFC-0002 Section 5.6) |
| Peer AgentId | The remote agent's 32-byte AgentId |
| Peer Public Key | The remote agent's ML-DSA-65 public key |
| Local AgentId | The local agent's 32-byte AgentId |
| Negotiated Version | The AAFP protocol version in use |
| Negotiated Extensions | The set of active extensions for this session |
| Peer Capabilities | The remote agent's CapabilityDescriptors |
| Authorization | The authorization state (if any tokens were exchanged) |
| Created At | Timestamp when the session was established |
| Last Activity | Timestamp of the last frame sent or received |

### 6.3 Session ID Properties

The Session ID MUST satisfy:

1. **Uniqueness**: No two sessions between any pair of agents share
   the same Session ID.
2. **Unpredictability**: An adversary cannot predict the Session ID
   before the handshake completes.
3. **Binding**: The Session ID is cryptographically bound to both
   agents' identities and the handshake transcript.

The derivation method is an implementation detail. A RECOMMENDED
approach is:

```
Session ID = HKDF-SHA256(
    input = handshake_transcript,
    info = "aafp-session-id-v1",
    length = 32
)
```

Implementations MAY use any method satisfying the above properties.

### 6.4 Session Reconnect (Future)

Session reconnect (resuming a previous session without a full
handshake) is deferred to a future RFC. The Session ID provides the
foundation for reconnect: a reconnect protocol would reference the
Session ID and prove possession of the session keys.

### 6.5 Session Expiry

Sessions do not have a protocol-level expiry. Implementations MAY
enforce their own session timeouts based on inactivity (using the
`Last Activity` timestamp). The PING/PONG frames (RFC-0002 Section
4.7/4.8) MAY be used for keepalive.

## 7. Authentication Flow

### 7.1 Full Handshake

```
Client                                          Server
  |                                               |
  |  QUIC connection + TLS handshake              |
  |  (X25519MLKEM768, ALPN=aafp/1)                |
  |<--------------------------------------------->|
  |                                               |
  |  HANDSHAKE frame (ClientHello)                |
  |  - protocol_version                           |
  |  - agent_id, public_key, nonce                |
  |  - capabilities                               |
  |  - extensions                                 |
  |  - signature (over ClientHello fields)        |
  |---------------------------------------------->|
  |                                               |
  |                  HANDSHAKE frame (ServerHello)|
  |                  - protocol_version           |
  |                  - agent_id, public_key, nonce|
  |                  - capabilities               |
  |                  - extensions                 |
  |                  - session_id                 |
  |                  - signature (over ServerHello|
  |                    fields)                    |
  |<----------------------------------------------|
  |                                               |
  |  Verify:                                      |
  |  - agent_id == SHA-256(public_key)            |
  |  - signature is valid                         |
  |  - expires_at > now (if AgentRecord provided) |
  |  - protocol_version is supported              |
  |                                               |
  |  HANDSHAKE frame (ClientFinished)             |
  |  - session_id (echoed)                        |
  |  - signature (over transcript)                |
  |---------------------------------------------->|
  |                                               |
  |                  Verify:                      |
  |                  - signature is valid         |
  |                  - session_id matches         |
  |                                               |
  |             Session Established                |
```

### 7.2 Authentication Verification Steps

**Client verifies ServerHello:**
1. `server_agent_id == SHA-256(server_public_key)`
2. `server_signature` is valid over ServerHello fields (excluding
   signature)
3. Server's AgentRecord (if provided via discovery) is valid and
   not expired
4. `protocol_version` is supported
5. `session_id` is present and non-empty

**Server verifies ClientFinished:**
1. `client_signature` is valid over the transcript
   (ClientHello || ServerHello)
2. `session_id` matches the one sent in ServerHello

### 7.3 Authorization During Handshake

Authorization tokens (e.g., UCAN tokens) MAY be exchanged during the
handshake via extensions (see RFC-0002 Section 6). The extension
type for authorization tokens is defined in RFC-0006.

If authorization tokens are exchanged, the session's `Authorization`
property is populated. Subsequent operations on the session MAY
check authorization before processing.

## 8. Security Considerations

### 8.1 Identity Binding

The AAFP handshake binds the TLS session to the agents' ML-DSA-65
identities. Even if the TLS certificate is compromised, the
application-layer signatures prevent identity forgery.

### 8.2 Replay Attacks

The handshake includes 32-byte random nonces from both sides. The
session ID is derived from the handshake transcript, which includes
both nonces. This prevents replay attacks: a recorded handshake
cannot be replayed because the session ID would differ.

### 8.3 Man-in-the-Middle

The TOFU model for TLS certificates is vulnerable to MITM on first
connection. This is mitigated by:

- The application-layer handshake verifying ML-DSA-65 identity
- AgentRecord signatures providing out-of-band verification
- Future support for ML-DSA-65 TLS certificates

Implementations SHOULD provide a mechanism for users to verify
agent identities out-of-band (e.g., by comparing AgentId hex
strings).

### 8.4 Key Compromise

If an agent's ML-DSA-65 secret key is compromised:

1. The attacker can impersonate the agent.
2. The attacker can sign AgentRecords and UCAN tokens.
3. Existing sessions are NOT compromised (they use TLS-derived
   session keys, not ML-DSA-65 keys).

Compromised agents MUST rotate their key pair and publish a new
AgentRecord. The protocol does not provide a revocation mechanism
in v1. Revocation is deferred to a future RFC.

### 8.5 Delegation Chain Attacks

UCAN delegation chains are vulnerable to:

- **Token theft**: A stolen token can be used until it expires.
  Mitigation: short expiry times.
- **Over-delegation**: An agent delegates more capability than it
  was granted. Mitigation: verification checks that each token in
  the chain delegates a subset of its parent's capabilities.
- **Chain length attacks**: Very long delegation chains consume
  verification time. Mitigation: implementations SHOULD enforce a
  maximum chain depth (RECOMMENDED: 8).

## 9. IANA Considerations

This RFC defines the following:

- **AgentRecord record_type values**: `"aafp-record-v1"` (future
  versions: `"aafp-record-v2"`, etc.)
- **CapabilityDescriptor field keys**: Integer keys 1–2 defined,
  3+ reserved.
- **MetadataValue variant tags**: 0x01–0x05 defined, 0x06+ reserved.
- **UCAN token field keys**: Integer keys 1–6 defined, 7+ reserved.

Registries are managed per RFC-0006.

## 10. References

- RFC 2119: Key words for use in RFCs
- RFC 7049: CBOR
- FIPS 203: ML-KEM
- FIPS 204: ML-DSA
- UCAN: User-Controlled Authorization Networks
