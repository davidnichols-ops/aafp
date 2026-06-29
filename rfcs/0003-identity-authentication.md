# RFC-0003: AAFP Identity & Authentication

```
Status:         Freeze Candidate (Revision 5)
Number:         0003
Title:          Agent Identity, AgentRecord, Capability Descriptors,
                Authorization, and Session Lifecycle
Author:         AAFP Project
Created:        2025-06-25
Revised:        2025-01-15 (Revision 4: SA-0001 and SA-0002
                clarifications — metadata field presence and empty
                CBOR map key-type)
                2025-01-16 (Revision 5: SA-0003 clarification —
                AgentRecord 30-day expiry is a deployment warning,
                not a verification-rejection requirement)
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

An AgentId is a 32-byte identifier derived from an agent's public key:

```
AgentId = SHA-256(public_key)
```

The hash function (SHA-256) is fixed for v1. Hash function agility
is an explicit future design consideration (see Section 2.2).

Properties:
- **Fixed 32 bytes**: Encoded as a CBOR byte string of length 32.
- **Quantum-safe**: SHA-256 is resistant to Shor's algorithm.
- **Collision-resistant**: 128-bit collision resistance.
- **Algorithm-independent**: AgentId derivation does not depend on
  the signature algorithm. The `key_algorithm` field (Section 2.3)
  identifies the signature algorithm; AgentId is always SHA-256 of
  the public key regardless of algorithm.

Implementations MUST verify that a received AgentId matches
`SHA-256(received_public_key)` during the handshake. If the
verification fails, the implementation MUST reject the handshake
with error code `2007` (INVALID_AGENT_ID).

If the ML-DSA-65 signature verification fails (the signature does
not validate against the public key), the implementation MUST
reject the handshake with error code `2001` (INVALID_SIGNATURE).

### 2.2 AgentId Encoding and Hash Agility

AgentIds are encoded as:

- **CBOR**: byte string (major type 2) of length 32
- **Hex**: 64-character lowercase hexadecimal string
- **Short form**: First 16 characters of the hex encoding, prefixed
  with `0x` (e.g., `0xa1b2c3d4e5f6a7b8`). Used for display only;
  NOT used for lookup or comparison.

#### Hash Agility (Future Design Consideration)

The hash function used for AgentId derivation (SHA-256) is fixed
for v1. Hash function agility is an explicit future design
consideration, NOT solved by the `key_algorithm` field (which
addresses signature algorithm agility only).

If SHA-256 needs to be replaced in a future version, the following
approaches may be considered:

1. **Multihash encoding**: Encode the hash function code in the
   AgentId (e.g., multihash format with 2-byte prefix). This
   changes AgentId size from 32 to 34 bytes.
2. **Hash algorithm field**: Add a `hash_algorithm` field to the
   handshake and AgentRecord (similar to `key_algorithm`). This
   preserves AgentId size but adds a field.
3. **New protocol version**: Define a new AgentId derivation for
   v2, with a migration path from v1.

The `key_algorithm` field (Section 2.3) addresses signature
algorithm agility but does NOT address hash function agility.
These are separate concerns:
- Signature algorithm: which algorithm signs the data (ML-DSA-65,
  ML-DSA-44, etc.)
- Hash function: which hash derives the AgentId (SHA-256, SHA-3,
  BLAKE3, etc.)

For v1, both are fixed (ML-DSA-65 and SHA-256). Future versions
may introduce agility for either or both.

### 2.3 Key Algorithm Registry

Each agent's public key is associated with a key algorithm that
identifies the signature scheme. The key algorithm is carried in
the handshake (ClientHello/ServerHello field 10) and in the
AgentRecord (field 9).

Key Algorithm Registry:

| Code | Name       | Public Key Size | Signature Size | Reference |
|------|------------|-----------------|----------------|-----------|
| 1    | ML-DSA-65  | 1952 bytes      | 3309 bytes     | FIPS 204  |
| 2    | ML-DSA-44  | 1312 bytes      | 2420 bytes     | FIPS 204  |
| 3    | ML-DSA-87  | 2592 bytes      | 4627 bytes     | FIPS 204  |
| 4    | SLH-DSA-128s | 32 bytes      | 7856 bytes     | FIPS 205  |
| 5–255| Reserved   | —               | —              | —         |

v1 implementations MUST support ML-DSA-65 (algorithm 1).
Implementations MAY support additional algorithms.

The AgentId derivation is the same for all algorithms:
`AgentId = SHA-256(public_key)`. This ensures AgentId stability
across algorithm changes (though a key rotation to a new algorithm
produces a new AgentId, since the public key changes).

### 2.4 ML-DSA-65 Key Pair

Each agent generates an ML-DSA-65 (FIPS 204) key pair:

- **Public key**: 1952 bytes
- **Secret key**: 4032 bytes
- **Signature**: 3309 bytes

The key pair is generated using the ML-DSA-65 key generation algorithm
as specified in FIPS 204. Implementations MUST use a cryptographically
secure random number generator for key generation.

#### Signing Mode

FIPS 204 specifies ML-DSA with hedged (randomized) signing as the
default. Implementations SHOULD use hedged signing as specified by
`ML-DSA.Sign()` with fresh randomness from an approved random bit
generator. Hedged signing provides side-channel resistance and is
essential where fault injection or side-channel attacks are a
concern.

Implementations MAY use deterministic signing (`ML-DSA.Sign()` with
the randomness input set to 32 zero bytes) for testing and
debugging. Deterministic signatures are valid and verifiable by all
implementations regardless of which mode the signer used; a
verifier cannot tell them apart.

### 2.5 Key Rotation

Agents MAY rotate their ML-DSA-65 key pair. Rotation produces a new
AgentId. The old AgentId and new AgentId have no cryptographic
relationship. Agents wishing to maintain identity across rotation
MUST use an out-of-band mechanism (e.g., a signed rotation statement
published to a directory service).

Key rotation is out of scope for AAFP v1. The protocol does not
provide an in-band key rotation mechanism.

### 2.6 AgentId Fingerprint

For out-of-band identity verification, implementations SHOULD
display AgentIds in a human-readable fingerprint format:

```
AAFP-<base32(first_16_bytes_of_AgentId)>-<CRC32>
```

Where:
- `base32` is RFC 4648 base32 encoding (no padding, uppercase)
- `first_16_bytes_of_AgentId` is the first 16 bytes of the 32-byte
  AgentId
- `CRC32` is a 4-character hex CRC-32 checksum of the first 16
  bytes, for typo detection

Example:
```
AgentId = 0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
Fingerprint = AAFP-A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2-3E7F8A9B
```

The fingerprint is for human verification only (e.g., comparing
displayed fingerprints between agents). It is NOT used for
protocol-level lookup or comparison. The full 32-byte AgentId is
used for all protocol operations.

Implementations MUST display the AgentId fingerprint when a new agent
connection is established (first connection to an unknown AgentId).
Implementations MUST provide an API for applications to retrieve and
compare fingerprints programmatically.

The fingerprint display MUST occur before the application begins
exchanging sensitive data with the new agent. Applications MAY
override this requirement if they perform their own out-of-band
identity verification.

Rationale: The TOFU model is vulnerable to man-in-the-middle attacks
on first connection. Mandatory fingerprint display ensures users have
the opportunity to detect MITM by comparing fingerprints through a
trusted channel (e.g., voice, QR code, pre-shared configuration).

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
    3: bstr,          // "public_key": public key (size depends on
                      //   key_algorithm, see field 9)
    4: [ *CapabilityDescriptor ],  // "capabilities"
    5: [ *tstr ],     // "endpoints": multiaddrs
    6: uint,          // "created_at": Unix timestamp (seconds)
    7: uint,          // "expires_at": Unix timestamp (seconds)
    8: bstr,          // "signature": ML-DSA-65 signature
    9: uint,          // "key_algorithm": Signature algorithm
                      //   (see Section 2.3). 1 = ML-DSA-65.
}
```

Fields are keyed by integers (not strings) for compact CBOR encoding.
The field key mapping is normative.

### 3.3 Field Semantics

| Key | Name | Type | Required | Description |
|-----|------|------|----------|-------------|
| 1 | record_type | tstr | Yes | MUST be `"aafp-record-v1"`. |
| 2 | agent_id | bstr(32) | Yes | SHA-256 of public_key. |
| 3 | public_key | bstr | Yes | Public key. Size depends on key_algorithm (field 9). For ML-DSA-65: 1952 bytes. |
| 4 | capabilities | array | Yes | CapabilityDescriptor array. May be empty. |
| 5 | endpoints | array | Yes | Multiaddr strings. May be empty. |
| 6 | created_at | uint | Yes | Unix timestamp when record was created. |
| 7 | expires_at | uint | Yes | Unix timestamp when record expires. |
| 8 | signature | bstr | Yes | ML-DSA-65 signature over the canonical CBOR encoding of fields 1–7 and 9 (excluding field 8). Size depends on key_algorithm. For ML-DSA-65: 3309 bytes. |
| 9 | key_algorithm | uint | Yes | Signature algorithm (see Section 2.3). Included in signature to prevent algorithm substitution attacks. |

### 3.4 Signature Computation

The signature is computed as follows:

1. Construct a CBOR map containing fields 1 through 7 and field 9
   (excluding field 8, the signature). The key_algorithm field (9)
   IS included in the signature to prevent algorithm substitution
   attacks.
2. Encode the map using canonical CBOR (see RFC-0002 Section 8).
3. Compute the signature input with domain separation:
   ```
   sig_input = "aafp-v1-record" || canonical_CBOR_bytes
   ```
4. Sign the signature input using ML-DSA-65 with the agent's
   secret key:
   ```
   signature = ML-DSA-65.Sign(secret_key, sig_input)
   ```
5. Place the signature in field 8.

The `"aafp-v1-record"` prefix is a domain separator that prevents
this signature from being valid in any other context (see
Section 3.5).

### 3.5 Domain Separation

All AAFP signatures are prefixed with a domain separator string to
prevent cross-protocol signature reuse. The domain separator is
prepended to the signature input before signing.

Defined domain separators:
- `"aafp-v1-handshake"`: Handshake signatures (ClientHello,
  ServerHello, ClientFinished) — see RFC-0002 Section 5.6
- `"aafp-v1-record"`: AgentRecord signatures (Section 3.4)
- `"aafp-v1-ucan"`: UCAN token signatures (Section 5.4)

Future signature contexts MUST define new domain separators
following the pattern `"aafp-v<version>-<context>"`.

The domain separator is encoded as its raw UTF-8 code units (bytes).
No null terminator, no length prefix, and no CBOR encoding is applied.
The signature input is the raw byte concatenation:

```
sig_input = domain_separator_utf8_bytes || message_bytes
```

For example, the domain separator `"aafp-v1-handshake"` is the 17-byte
UTF-8 sequence (no null terminator):
`0x61 0x61 0x66 0x70 0x2D 0x76 0x31 0x2D 0x68 0x61 0x6E 0x64 0x73 0x68
0x61 0x6B 0x65`

The set of domain separators is prefix-free (no separator is a
prefix of another), satisfying the IETF CFRG requirement for
domain separation in signature schemes.

### 3.6 Verification

To verify an AgentRecord:

1. Decode the CBOR map.
2. Verify that `agent_id == SHA-256(public_key)`. If not, reject
   with error code 2007 (INVALID_AGENT_ID).
3. Extract fields 1–7 and field 9 (key_algorithm), and re-encode
   using canonical CBOR.
4. Compute the signature input:
   `sig_input = "aafp-v1-record" || canonical_CBOR_bytes`
5. Verify the ML-DSA-65 signature in field 8 against `sig_input`
   using the public key in field 3. If verification fails, reject
   with error code 2001 (INVALID_SIGNATURE).
6. Check that `expires_at > current_time`. If expired, reject with
   error code 2002 (IDENTITY_EXPIRED).
7. Check that `record_type == "aafp-record-v1"`. If not, reject.
8. Check that `key_algorithm` (field 9) is a supported algorithm
   (see Section 2.3). If not supported, reject with error code
   2010 (UNSUPPORTED_ALGORITHM).

### 3.7 Forward Compatibility

Future versions of AgentRecord MAY add new fields with integer keys
≥ 10. Implementations MUST ignore unknown fields. Implementations
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
    2: { *tstr => MetadataValue },  // "metadata": MUST be present, MAY be empty
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
| 2 | metadata | map | Yes | Metadata map. MUST be present. MAY be empty. When empty, encoded as an empty CBOR map (`a0`, major type 5, 0 entries). See Section 4.5 for key type and ordering rules. |

**Clarification (Revision 4)**: The `metadata` field (key 2) MUST
always be present in every CapabilityDescriptor on the wire. An
empty metadata map MUST be encoded as `a0` (empty CBOR map), not
omitted. This ensures deterministic encoding across implementations
and prevents signature verification failures caused by inconsistent
field presence. Implementations MUST NOT omit key 2, even when the
metadata map is empty.

### 4.5 Metadata Map

The metadata map uses `BTreeMap` ordering (lexicographic key ordering)
for deterministic serialization. This is critical for:

- **Signature verification**: AgentRecord signatures cover
  CapabilityDescriptors. Non-deterministic map ordering would break
  cross-implementation signature verification.
- **Caching**: Deterministic encoding enables byte-level comparison.

**Empty map key type (Revision 4 clarification)**: The metadata map
is defined as `map<tstr, MetadataValue>` (string-keyed). When the
map is empty, CBOR encodes it as `a0` (major type 5, 0 entries).
Because CBOR does not distinguish between empty int-keyed maps and
empty string-keyed maps in the encoded byte `0xa0`, the key type
MUST be determined from the enclosing schema, not from the CBOR
encoding. Decoders MUST interpret an empty map in the metadata field
(key 2) as a string-keyed map, regardless of the CBOR major type
implied by the `a0` encoding. This rule applies to all AAFP fields
with a schema-defined key type (see RFC-0002 §8.1).

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
    6: bstr,          // "signature": ML-DSA-65 signature over
                      //   "aafp-v1-ucan" || canonical_CBOR(fields 1-5)
}
```

The UCAN token signature (field 6) is computed over:
```
sig_input = "aafp-v1-ucan" || canonical_CBOR(fields 1-5)
signature = ML-DSA-65.Sign(secret_key, sig_input)
```

The `"aafp-v1-ucan"` domain separator prevents this signature from
being valid in any other context (see Section 3.5).

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
| Session ID | Cryptographically unique identifier (see RFC-0002 Section 5.7) |
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
   agents' identities, the handshake transcript, and the TLS channel
   binding.

The Session ID derivation is normative and defined in RFC-0002
Section 5.7:

```
prk = HKDF-Extract(
    salt = client_nonce || server_nonce,
    IKM  = transcript_hash)
session_id = HKDF-Expand(prk, info = "aafp-session-id-v1", L = 32)
```

All implementations MUST use this exact derivation. The
`transcript_hash` includes the TLS channel binding value (see
RFC-0002 Section 5.6), ensuring the Session ID is bound to the
specific TLS session.

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
  |  Both sides compute:                          |
  |  tls_binding = TLS-Exporter(                  |
  |      "EXPORTER-AAFP-Channel-Binding", "", 32) |
  |  h = SHA-256(tls_binding)                     |
  |                                               |
  |  HANDSHAKE frame (ClientHello)                |
  |  - protocol_version                           |
  |  - agent_id, public_key, nonce                |
  |  - capabilities                               |
  |  - extensions                                 |
  |  - expires_at                                 |
  |  - key_algorithm                              |
  |  - receiver_mac (optional, DoS profile)       |
  |  - signature (over transcript hash with       |
  |    domain separator "aafp-v1-handshake")      |
  |---------------------------------------------->|
  |                                               |
  |  h = SHA-256(h || CBOR(ClientHello w/o sig,   |
  |                       receiver_mac))          |
  |                                               |
  |                  HANDSHAKE frame (ServerHello)|
  |                  - protocol_version           |
  |                  - agent_id, public_key, nonce|
  |                  - capabilities               |
  |                  - extensions (accepted)      |
  |                  - session_id                 |
  |                  - expires_at                 |
  |                  - key_algorithm              |
  |                  - signature (over transcript |
  |                    hash with domain separator)|
  |<----------------------------------------------|
  |                                               |
  |  h = SHA-256(h || CBOR(ServerHello w/o sig))  |
  |                                               |
  |  Verify:                                      |
  |  - agent_id == SHA-256(public_key) [2007]     |
  |  - signature is valid [2001]                  |
  |  - expires_at > now [2002]                    |
  |  - key_algorithm is supported [2010]          |
  |  - protocol_version is supported [2004]       |
  |  - session_id derivation matches              |
  |                                               |
  |  HANDSHAKE frame (ClientFinished)             |
  |  - session_id (echoed)                        |
  |  - signature (over transcript hash h with     |
  |    domain separator "aafp-v1-handshake")      |
  |---------------------------------------------->|
  |                                               |
  |                  Verify:                      |
  |                  - signature is valid [2001]  |
  |                  - session_id matches         |
  |                                               |
  |             Session Established                |
```

### 7.2 Authentication Verification Steps

**Client verifies ServerHello:**
1. `server_agent_id == SHA-256(server_public_key)`. If not, reject
   with error code 2007 (INVALID_AGENT_ID).
2. `server_signature` is valid over the transcript hash (see
   RFC-0002 Section 5.6) with domain separator "aafp-v1-handshake".
   If not, reject with error code 2001 (INVALID_SIGNATURE).
3. `server_expires_at > current_time`. If expired, reject with
   error code 2002 (IDENTITY_EXPIRED). When the client has the
   server's AgentRecord (from discovery), the AgentRecord's
   `expires_at` is authoritative. If the handshake `expires_at`
   differs from the AgentRecord's `expires_at`, the client SHOULD
   use the earlier (sooner) expiry.
4. `server_key_algorithm` is a supported algorithm (see Section 2.3).
   If not, reject with error code 2010 (UNSUPPORTED_ALGORITHM).
5. `protocol_version` is supported. If not, reject with error code
   2004 (VERSION_MISMATCH).
6. `session_id` is present and correctly derived (see RFC-0002
   Section 5.7).
7. Server's AgentRecord (if available from discovery) is valid and
   not expired.

**Server verifies ClientHello:**
1. If DoS mitigation profile is active (see RFC-0002 Section 5.8),
   verify `receiver_mac` first. If invalid, reject with error code
   2009 (RECEIVER_MAC_INVALID) without performing signature
   verification.
2. `client_agent_id == SHA-256(client_public_key)`. If not, reject
   with error code 2007 (INVALID_AGENT_ID).
3. `client_signature` is valid over the transcript hash with domain
   separator "aafp-v1-handshake". If not, reject with error code
   2001 (INVALID_SIGNATURE).
4. `client_expires_at > current_time`. If expired, reject with
   error code 2002 (IDENTITY_EXPIRED). Trust model: the handshake
   `expires_at` is a self-attested claim. When the server has the
   client's AgentRecord, the AgentRecord's `expires_at` is
   authoritative. If they differ, the server SHOULD use the earlier
   (sooner) expiry.
5. `client_key_algorithm` is a supported algorithm. If not, reject
   with error code 2010 (UNSUPPORTED_ALGORITHM).
6. `protocol_version` is supported. If not, reject with error code
   2004 (VERSION_MISMATCH).

**Server verifies ClientFinished:**
1. `client_signature` is valid over the transcript hash `h` (see
   RFC-0002 Section 5.6) with domain separator "aafp-v1-handshake".
   If not, reject with error code 2001 (INVALID_SIGNATURE).
2. `session_id` matches the one sent in ServerHello.

### 7.3 Authorization During Handshake

Authorization tokens (e.g., UCAN tokens) MAY be exchanged during the
handshake via handshake extensions (see RFC-0002 Section 6.4). The
extension type for authorization tokens is defined in RFC-0006.

If authorization tokens are exchanged, the session's `Authorization`
property is populated. Subsequent operations on the session MAY
check authorization before processing.

## 8. Security Considerations

### 8.1 Identity Binding

The AAFP application-layer handshake binds the TLS session to the
agents' ML-DSA-65 identities via TLS channel binding. The TLS
exporter value (RFC 8446 Section 7.5, using the label
"EXPORTER-AAFP-Channel-Binding" per RFC 9266) is included in the
handshake transcript hash (RFC-0002 Section 5.6). This prevents
relay attacks: an attacker who terminates TLS on both sides cannot
relay AAFP handshake messages because the transcript hashes will
differ (the TLS sessions differ), causing signature verification
failure.

Even if the TLS certificate is compromised, the application-layer
signatures prevent identity forgery.

### 8.2 Replay Attacks

The handshake includes 32-byte random nonces from both sides. The
session ID is derived from the handshake transcript, which includes
both nonces. This prevents replay attacks: a recorded handshake
cannot be replayed because the session ID would differ.

### 8.3 Man-in-the-Middle

The TOFU model for TLS certificates is vulnerable to MITM on first
connection. This is mitigated by:

- The application-layer handshake verifying ML-DSA-65 identity
- TLS channel binding preventing relay attacks (Section 8.1)
- AgentRecord signatures providing out-of-band verification
- AgentId fingerprints (Section 2.6) for human verification
- Future support for ML-DSA-65 TLS certificates

Implementations SHOULD provide a mechanism for users to verify
agent identities out-of-band using the fingerprint format defined
in Section 2.6. Users compare fingerprints through a trusted
channel (e.g., voice, QR code, or pre-shared configuration) to
detect man-in-the-middle attacks on first connection.

### 8.4 Key Compromise and Revocation

#### Blast Radius

If an agent's ML-DSA-65 secret key is compromised:

1. The attacker can impersonate the agent to all peers.
2. The attacker can sign AgentRecords and UCAN tokens.
3. The attacker can delegate capabilities to other agents.
4. The attacker can advertise false capabilities in the DHT.
5. **Existing sessions are NOT compromised**: they use TLS-derived
   session keys, not ML-DSA-65 keys. Active sessions remain secure
   until they expire or are closed.
6. **Past sessions are NOT compromised**: TLS 1.3 provides forward
   secrecy for transport-layer traffic. However, if the attacker
   recorded handshake messages, they can verify (but not forge)
   past signatures.
7. **Application-layer identity has NO forward secrecy**: The
   attacker can forge AgentRecords and UCAN tokens with past
   timestamps (subject to `expires_at` validation by verifiers).

#### Compromise Response

Compromised agents MUST:
1. Generate a new ML-DSA-65 key pair.
2. Publish a new AgentRecord with the new public key and a new
   AgentId.
3. Notify known peers out-of-band of the key rotation.
4. Revoke all UCAN tokens signed by the compromised key (by not
   renewing them and waiting for expiry).

#### Revocation (v1 Limitation)

AAFP v1 does NOT provide an in-protocol revocation mechanism. A
compromised key remains valid until the AgentRecord's `expires_at`
timestamp. This is a known limitation.

To mitigate the impact of key compromise:

1. Implementations MUST support AgentRecord expiry no longer than
   30 days (2,592,000 seconds). Implementations MUST warn users if
   an AgentRecord's `expires_at` exceeds 30 days from the current
   time.

   The 30-day limit in point 1 is a deployment mitigation, not a
   verification requirement. The verification procedure in §3.6
   does NOT reject records whose lifetime exceeds 30 days.
   Implementations MUST warn users when
   `expires_at - current_time > 2,592,000`. The warning predicate
   is computed from the current time, not from `created_at`.
2. Implementations SHOULD renew AgentRecords every 7 days to keep
   the expiry window short.
3. The `expires_at` field in the handshake (RFC-0002 Sections 5.3,
   5.4) allows peers to verify expiry without discovery lookup.
4. Applications SHOULD implement out-of-band revocation checking
   (e.g., a revocation list published out-of-band) if the threat
   model requires it.

#### Future Revocation Mechanism

A future RFC will specify a revocation mechanism (see RFC-0006
future work registry). The design will consider:

- **Revocation lists**: Signed lists of revoked AgentIds, published
  to bootstrap nodes or a dedicated service.
- **Short-lived records**: AgentRecords with very short expiry
  (e.g., 1 hour), requiring frequent renewal. Revocation is
  achieved by not renewing.
- **Delegation-based revocation**: A trusted authority signs
  revocation statements. This requires a trust model that AAFP v1
  does not define.

The `key_algorithm` field (Section 2.3) and the extension mechanism
(RFC-0002 Section 6.4) provide the foundation for future revocation
extensions.

### 8.5 Delegation Chain Attacks

UCAN delegation chains are vulnerable to:

- **Token theft**: A stolen token can be used until it expires.
  Mitigation: short expiry times.
- **Over-delegation**: An agent delegates more capability than it
  was granted. Mitigation: verification checks that each token in
  the chain delegates a subset of its parent's capabilities.
- **Chain length attacks**: Very long delegation chains consume
  verification time. Mitigation: implementations MUST enforce a
  maximum UCAN delegation chain depth of 8. Tokens that exceed
  this depth MUST be rejected with error code 3006
  (DELEGATION_DEPTH_EXCEEDED).

Implementations SHOULD use short UCAN expiry times (RECOMMENDED: 1
hour / 3600 seconds) to limit the blast radius of token theft.

### 8.6 Key Management Requirements

#### Key Generation

ML-DSA-65 key pairs MUST be generated using the algorithm specified
in FIPS 204, using a cryptographically secure random number
generator. Implementations SHOULD use hedged (randomized) signing
as specified by FIPS 204 for side-channel resistance.

#### Key Storage

Implementations MUST protect ML-DSA-65 secret keys at rest using
encryption. Implementations SHOULD use hardware-backed key storage
(e.g., HSM, TPM, Secure Enclave) when available.

Secret keys MUST NOT be logged, transmitted in plaintext, or stored
in world-readable files. Implementations MUST zeroize secret key
material from memory when no longer needed.

#### Key Rotation

AAFP v1 does not provide an in-protocol key rotation mechanism (see
Section 2.5). Key rotation produces a new AgentId, requiring
out-of-band notification to peers. Applications that require key
rotation SHOULD:

1. Generate the new key pair before retiring the old key.
2. Publish the new AgentRecord before notifying peers.
3. Notify peers out-of-band of the new AgentId.
4. Maintain the old key until all known peers have migrated.

A future RFC will specify an in-protocol key rotation mechanism.

#### Key Compromise Detection

Implementations SHOULD provide mechanisms to detect key compromise,
such as:
- Monitoring for unexpected AgentRecord publications
- Alerting on connections from unexpected IP addresses
- Logging all signing operations for audit

These mechanisms are application-specific and not normatively
specified in AAFP v1.

#### Forward Secrecy Properties

- **Transport-layer traffic**: Forward secrecy is provided by TLS 1.3
  with X25519MLKEM768. If TLS session keys are compromised in the
  future, past transport-layer traffic remains confidential.
- **Application-layer identity**: NO forward secrecy. AgentRecords
  and UCAN tokens are self-signed with ML-DSA-65. If the secret key
  is compromised, the attacker can forge records and tokens with
  arbitrary past timestamps (subject to `expires_at` validation).
- **Session metadata**: Forward secrecy depends on TLS. If TLS
  session keys are compromised, session metadata (Session ID,
  capabilities) can be derived from recorded handshake messages.

The lack of forward secrecy for application-layer identity is a
known limitation. Short AgentRecord expiry times (30 days max, see
Section 8.4) limit the window of vulnerability.

## 9. IANA Considerations

This RFC defines the following:

- **AgentRecord record_type values**: `"aafp-record-v1"` (future
  versions: `"aafp-record-v2"`, etc.)
- **AgentRecord field keys**: Integer keys 1–9 defined, 10+ reserved.
- **CapabilityDescriptor field keys**: Integer keys 1–2 defined,
  3+ reserved.
- **MetadataValue variant tags**: 0x01–0x05 defined, 0x06+ reserved.
- **UCAN token field keys**: Integer keys 1–6 defined, 7+ reserved.
- **Key Algorithm Registry**: Values 1–255 (see Section 2.3)
- **Domain Separators**: "aafp-v1-handshake", "aafp-v1-record",
  "aafp-v1-ucan" (see Section 3.5)

Registries are managed per RFC-0006.

## 10. References

- RFC 2119: Key words for use in RFCs
- RFC 8949: Concise Binary Object Representation (CBOR) [obsoletes
  RFC 7049]
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 9266: Channel Bindings for TLS 1.3
- RFC 4648: The Base16, Base32, and Base64 Data Encodings
- FIPS 203: Module-Lattice-Based Key-Encapsulation (ML-KEM)
- FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)
- UCAN: User-Controlled Authorization Networks
- RFC-0001: AAFP Protocol Overview
- RFC-0002: AAFP Transport & Framing
- RFC-0006: AAFP Versioning & Compatibility
