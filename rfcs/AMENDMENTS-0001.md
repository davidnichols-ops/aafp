# AAFP RFC Amendments: Critical and High-Severity Issues

```
Document:         AMENDMENTS-0001
Date:             2025-06-25
Status:           Proposed
Scope:            Amendments to RFC-0001 through RFC-0006 addressing
                  all Critical (6) and High-severity (12) issues from
                  REVIEW-0001 and REVIEW-0002.
Design Principle: Amendments are minimal and targeted. Each amendment
                  changes only what is necessary to resolve the issue.
                  Existing RFC structure and numbering are preserved
                  where possible.
```

---

## Architecture Question Framework

Before accepting any amendment, four questions must be answered:

1. **Is this a protocol requirement or merely an implementation
   recommendation?** — Does the issue affect what goes on the wire,
   or how implementations process it?

2. **Does this need to be normative (MUST/MUST NOT) or informative
   (SHOULD/MAY)?** — Is the behavior required for interoperability,
   or is it guidance for implementers?

3. **Will this decision be expensive or impossible to change after
   independent implementations exist?** — Is this a one-way door?

4. **Does adopting an existing standard reduce long-term maintenance
   compared to inventing a new mechanism?** — Is there a proven
   pattern we should follow rather than designing something new?

These questions are answered for each amendment below.

---

## Critical Issues

---

### Amendment C1: Standardize CBOR Map Key Convention

**Issue**: CBOR map key type inconsistency — RFC-0002 uses string keys
for handshake messages and RPC structures; RFC-0003 and RFC-0005 use
integer keys for AgentRecord, CapabilityDescriptor, UcanToken, and RPC
error objects.

**Proposed Amendment**:

All AAFP CBOR structures MUST use integer keys. The string-keyed
schemas in RFC-0002 Sections 4.3–4.6 and 5.3–5.5 are replaced with
integer-keyed schemas. A normative key mapping table is added to
RFC-0002.

**Affected RFCs**: RFC-0002 (Sections 4.3, 4.4, 4.5, 4.6, 5.3, 5.4,
5.5), RFC-0005 (Section 6.1 — already uses integer keys, confirm
consistency).

**Specific Changes to RFC-0002**:

Section 4.3 (RpcRequest):
```cbor
RpcRequest = {
    1: uint,       // "id": Correlation ID (unique per connection)
    2: tstr,       // "method": Method name
    3: any,        // "params": Method parameters (see Amendment C4)
}
```

Section 4.4 (RpcResponse):
```cbor
RpcResponse = {
    1: uint,                    // "id": Matches the request ID
    2: any / null,              // "result": Result data (null if error)
    3: {                        // "error": Error object (null if success)
        1: uint,                //   "code": Error code (see RFC-0005)
        2: tstr,                //   "message": Human-readable message
        3: bstr / null,         //   "data": Optional structured data
    } / null,
}
```

Section 4.5 (CloseMessage):
```cbor
CloseMessage = {
    1: uint,       // "code": Close reason code (see RFC-0005)
    2: tstr,       // "message": Human-readable close reason
}
```

Section 4.6 (ErrorMessage):
```cbor
ErrorMessage = {
    1: uint,            // "code": Error code from registry
    2: tstr,            // "message": Human-readable description
    3: bstr / null,     // "data": Optional structured error data
    4: bool,            // "fatal": If true, connection must close
}
```

Section 5.3 (ClientHello):
```cbor
ClientHello = {
    1: uint,       // "protocol_version": AAFP version (1)
    2: bstr,       // "agent_id": 32-byte AgentId
    3: bstr,       // "public_key": ML-DSA-65 public key (1952 bytes)
    4: bstr,       // "nonce": 32-byte random nonce
    5: [ *CapabilityDescriptor ],  // "capabilities"
    6: [ *ExtensionEntry ],        // "extensions" (see Amendment C3)
    7: bstr,       // "signature": ML-DSA-65 signature (see Amendment C2)
}
```

Section 5.4 (ServerHello):
```cbor
ServerHello = {
    1: uint,       // "protocol_version": AAFP version (1)
    2: bstr,       // "agent_id": 32-byte AgentId
    3: bstr,       // "public_key": ML-DSA-65 public key (1952 bytes)
    4: bstr,       // "nonce": 32-byte random nonce
    5: [ *CapabilityDescriptor ],  // "capabilities"
    6: [ *ExtensionEntry ],        // "extensions" (accepted subset)
    7: bstr,       // "session_id": Session identifier (see Amendment C2)
    8: bstr,       // "signature": ML-DSA-65 signature
}
```

Section 5.5 (ClientFinished):
```cbor
ClientFinished = {
    1: bstr,       // "session_id": Echoed from ServerHello
    2: bstr,       // "signature": ML-DSA-65 signature (see Amendment C2)
}
```

A normative key mapping table is added to RFC-0002 Section 8:

```
| Structure         | Key | Field Name          |
|-------------------|-----|---------------------|
| RpcRequest        | 1   | id                  |
| RpcRequest        | 2   | method              |
| RpcRequest        | 3   | params              |
| RpcResponse       | 1   | id                  |
| RpcResponse       | 2   | result              |
| RpcResponse       | 3   | error               |
| RpcResponse.error | 1   | code                |
| RpcResponse.error | 2   | message             |
| RpcResponse.error | 3   | data                |
| CloseMessage      | 1   | code                |
| CloseMessage      | 2   | message             |
| ErrorMessage      | 1   | code                |
| ErrorMessage      | 2   | message             |
| ErrorMessage      | 3   | data                |
| ErrorMessage      | 4   | fatal               |
| ClientHello       | 1   | protocol_version    |
| ClientHello       | 2   | agent_id            |
| ClientHello       | 3   | public_key          |
| ClientHello       | 4   | nonce               |
| ClientHello       | 5   | capabilities        |
| ClientHello       | 6   | extensions          |
| ClientHello       | 7   | signature           |
| ServerHello       | 1   | protocol_version    |
| ServerHello       | 2   | agent_id            |
| ServerHello       | 3   | public_key          |
| ServerHello       | 4   | nonce               |
| ServerHello       | 5   | capabilities        |
| ServerHello       | 6   | extensions          |
| ServerHello       | 7   | session_id          |
| ServerHello       | 8   | signature           |
| ClientFinished    | 1   | session_id          |
| ClientFinished    | 2   | signature           |
```

**Rationale**: CBOR map key type affects canonical encoding, which
affects signature verification. Two implementations using different
key types will produce different byte sequences for the same logical
value, causing signature verification failures. Integer keys are more
compact (1-byte encoding for keys 1–23 vs multi-byte string keys) and
are already used in RFC-0003 and RFC-0005. Standardizing on integer
keys everywhere ensures consistency.

**External Precedent**: COSE (RFC 8152) uses integer keys for CBOR
maps. CBOR Web Tokens (RFC 8392) use integer keys. The IETF CBOR
working group recommends integer keys for protocol-defined structures
to minimize encoding size and ensure deterministic sorting.

**Wire Protocol Change**: Yes — resolves ambiguity that would otherwise
cause wire-level incompatibility. Since no independent implementations
exist yet, this is a specification correction, not a breaking change.

**Backward Compatibility**: Breaks compatibility with the v0.1 MVP
(which used string keys in some structures). This is justified because
v0.1 is explicitly not v1-compatible (RFC-0006 Section 2.1). No
independent v1 implementations exist.

**New Tradeoffs**:
- *Interoperability*: Dramatically improved. All implementations now
  produce identical wire formats.
- *Debuggability*: Slightly reduced. Integer keys are less
  self-documenting than string keys. Mitigated by the normative key
  mapping table.
- *Bandwidth*: Improved. Integer keys 1–23 encode in 1 byte; string
  keys like "protocol_version" encode in 18 bytes.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. The key type is on the wire and affects signature
   verification.
2. *Normative or informative?* — Normative (MUST). Interoperability
   requires identical key types.
3. *Expensive to change later?* — Yes. Once implementations exist,
   changing key types invalidates all signatures and breaks
   interoperability. This is a one-way door.
4. *Adopt existing standard?* — Yes. COSE (RFC 8152) and CWT (RFC 8392)
   establish integer-keyed CBOR maps as the IETF pattern. Following
   this reduces long-term maintenance by aligning with the broader
   CBOR ecosystem.

---

### Amendment C2: Define Handshake Transcript Construction

**Issue**: The ClientFinished signature is "over the transcript" but
the transcript's byte-level construction is never specified.

**Proposed Amendment**:

RFC-0002 Section 5.5 is amended to define the transcript as a running
SHA-256 hash. A new Section 5.6 "Transcript Hash" is added.

**Affected RFCs**: RFC-0002 (Sections 5.3, 5.4, 5.5, new 5.6),
RFC-0003 (Section 6.3 — Session ID derivation references transcript).

**Specific Changes to RFC-0002**:

Add new Section 5.6 (Transcript Hash), renumbering existing 5.6 to
5.7, 5.7 to 5.8:

```
### 5.6 Transcript Hash

The handshake transcript hash is a running SHA-256 hash over the
canonical CBOR encodings of handshake messages, prefixed with the
TLS channel binding value (see Amendment C5).

The transcript hash is computed as follows:

1. After TLS handshake completion, both sides compute the TLS
   channel binding:
   ```
   tls_binding = TLS-Exporter("aafp-channel-binding", "", 32)
   ```
   This is a 32-byte value derived from the TLS session keys. It
   is unique to the TLS session and cannot be computed by an
   attacker who does not possess the TLS session keys.

2. Initialize the transcript hash:
   ```
   h = SHA-256(tls_binding)
   ```

3. After sending or receiving ClientHello, update:
   ```
   h = SHA-256(h || canonical_CBOR(ClientHello_without_signature))
   ```
   Where `canonical_CBOR(ClientHello_without_signature)` is the
   canonical CBOR encoding of the ClientHello map excluding the
   signature field (key 7).

4. After sending or receiving ServerHello, update:
   ```
   h = SHA-256(h || canonical_CBOR(ServerHello_without_signature))
   ```
   Where `canonical_CBOR(ServerHello_without_signature)` is the
   canonical CBOR encoding of the ServerHello map excluding the
   signature field (key 8).

5. The final transcript hash `h` is used for:
   - ClientFinished signature (Section 5.5)
   - Session ID derivation (RFC-0003 Section 6.3)

The ClientHello and ServerHello signatures (keys 7 and 8) are
computed over the transcript hash at the point where that message
is sent:

- ClientHello.signature = ML-DSA-65.Sign(
      secret_key,
      "aafp-v1-handshake" || SHA-256(tls_binding || canonical_CBOR(ClientHello_without_signature)))

- ServerHello.signature = ML-DSA-65.Sign(
      secret_key,
      "aafp-v1-handshake" || SHA-256(tls_binding || canonical_CBOR(ClientHello_without_signature) || canonical_CBOR(ServerHello_without_signature)))

- ClientFinished.signature = ML-DSA-65.Sign(
      secret_key,
      "aafp-v1-handshake" || h)

The "aafp-v1-handshake" prefix is a domain separator (see Amendment
H1).
```

Update Section 5.5 (ClientFinished) to reference the transcript hash:
```
The ClientFinished signature is computed over the transcript hash
as defined in Section 5.6.
```

Update Section 5.3 (ClientHello) signature comment:
```
7: bstr,       // "signature": ML-DSA-65 signature over
               // SHA-256(tls_binding || canonical_CBOR(this map
               // excluding signature)) with domain separator
               // "aafp-v1-handshake" (see Section 5.6)
```

Update Section 5.4 (ServerHello) signature comment similarly.

**Rationale**: The transcript hash is the cryptographic backbone of
the handshake. Without a precise definition, independent
implementations will compute different byte sequences, causing
signature verification failures. This is the single most likely
source of interimplementation failure (~95% divergence probability
per REVIEW-0002).

The running hash pattern (hashing incrementally as messages arrive)
is more memory-efficient than storing all messages and hashing at
the end. It also matches the pattern used by TLS 1.3 and Noise.

Including the TLS channel binding (`tls_binding`) in the transcript
prevents relay attacks (see Amendment C5).

**External Precedent**:
- TLS 1.3 (RFC 8446 Section 4.4.1): `Transcript-Hash(M1, M2, ... Mn)
  = Hash(M1 || M2 || ... || Mn)` — running hash over handshake
  messages.
- Noise Protocol Framework (Section 5.2): `MixHash(data): h =
  HASH(h || data)` — running hash updated after each message.
- Both include all handshake data in the hash; AAFP follows this
  pattern but uses canonical CBOR encodings rather than raw message
  bytes (since AAFP messages are CBOR, not fixed-format binary).

**Wire Protocol Change**: Yes — defines the normative transcript
construction. No independent implementations exist, so this is a
specification completion, not a breaking change.

**Backward Compatibility**: Breaks v0.1 MVP compatibility (which had
no transcript definition). Justified because v0.1 is not v1-compatible.

**New Tradeoffs**:
- *Interoperability*: Dramatically improved. All implementations now
  compute identical transcript hashes.
- *Security*: Improved. The running hash with TLS channel binding
  prevents relay attacks.
- *Memory*: Improved. Running hash requires O(1) memory (32-byte
  hash state) vs O(N) for storing all messages.
- *Latency*: Negligible impact. SHA-256 of ~10KB is ~10μs.
- *Complexity*: Slightly increased. Implementations must maintain
  running hash state during handshake. This is standard practice
  (TLS and Noise both require it).

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. The transcript is on the wire (it determines signature
   values) and must be identical across implementations.
2. *Normative or informative?* — Normative (MUST). Signature
   verification requires identical transcript computation.
3. *Expensive to change later?* — Yes, extremely. Changing the
   transcript construction invalidates all existing signatures and
   session IDs. This is a one-way door that must be correct before v1.
4. *Adopt existing standard?* — Yes. The running hash pattern is
   established by TLS 1.3 (RFC 8446 §4.4.1) and Noise (§5.2). Adopting
   this pattern reduces maintenance by aligning with widely understood
   conventions. AAFP adapts the pattern to CBOR-encoded messages
   rather than fixed-format binary messages, which is necessary
   because AAFP uses CBOR for all structures.

---

### Amendment C3: Define Handshake Extension Format and Negotiation Protocol

**Issue**: The `extensions` field in ClientHello/ServerHello is
described as "supported extensions" but its encoding is never
specified. The extension negotiation protocol (how extensions are
proposed, accepted, rejected) is undefined.

**Proposed Amendment**:

RFC-0002 Section 5.3, 5.4, and 6.3 are amended to define the
handshake extension format and negotiation protocol.

**Affected RFCs**: RFC-0002 (Sections 5.3, 5.4, 6.3), RFC-0006
(Section 5.3 — feature negotiation references).

**Specific Changes to RFC-0002**:

Add a new subsection 6.4 (Handshake Extension Negotiation):

```
### 6.4 Handshake Extension Negotiation

Extensions are negotiated during the handshake. The ClientHello
includes a list of proposed extensions; the ServerHello includes a
list of accepted extensions (a subset of the client's proposals).

#### Extension Entry Format

Each extension entry in the handshake is a CBOR map:

ExtensionEntry = {
    1: uint,       // "type": Extension type (see RFC-0006 registry)
    2: bstr,       // "data": Extension-type-specific data
}

The ClientHello.extensions field (key 6) is a CBOR array of
ExtensionEntry maps, listing all extensions the client proposes.

The ServerHello.extensions field (key 6) is a CBOR array of
ExtensionEntry maps, listing the extensions the server accepts.
This MUST be a subset of the extensions proposed by the client.
The server MUST NOT include extensions that the client did not
propose.

#### Negotiation Rules

1. The client proposes extensions by including ExtensionEntry maps
   in ClientHello.extensions.
2. The server accepts a subset by including ExtensionEntry maps in
   ServerHello.extensions. The server MAY include extension data
   that differs from the client's proposal (e.g., selecting
   parameters).
3. Extensions not included in ServerHello.extensions are NOT active
   for the session.
4. If the client proposed a mandatory extension (identified by type
   in the 0x0000–0x3FFF range with the critical bit semantics per
   RFC-0006) and the server did not accept it, the server MUST send
   an ERROR frame with code 2005 (UNSUPPORTED_EXTENSIONS) and close
   the connection.
5. Using a non-negotiated extension in a subsequent frame (after the
   handshake) is a protocol error. The receiver MUST send an ERROR
   frame with code 8007 (INVALID_FLAGS) and close the connection.

#### Relationship to Frame Extensions

Frame-level extensions (Section 6.1) use a binary encoding in the
frame body's Extension section. Handshake-level extensions use CBOR
ExtensionEntry maps in the handshake messages. These are distinct
mechanisms:

- Handshake extensions negotiate session-wide features.
- Frame extensions carry per-frame metadata.

A handshake extension MAY correspond to a frame extension type. For
example, a compression extension negotiated in the handshake would
enable the COMPRESSED flag in DATA frames.
```

Update ClientHello and ServerHello schemas (key 6):
```
6: [ *ExtensionEntry ],  // "extensions": Proposed (ClientHello) or
                         // accepted (ServerHello) extensions
                         // (see Section 6.4)
```

**Rationale**: Extension negotiation is the primary forward-
compatibility mechanism. Without a defined format and negotiation
protocol, implementations cannot negotiate features. The
authorization token exchange (RFC-0003 Section 7.3) depends on
extensions but cannot function without this definition.

**External Precedent**:
- TLS 1.3 (RFC 8446 Section 4.2): ClientHello includes
  `extensions` as a vector of (type, length, data) tuples.
  ServerHello includes accepted extensions. EncryptedExtensions
  carries server-only extensions. The negotiation is: client
  proposes, server accepts subset.
- QUIC (RFC 9000 Section 7.4): Transport parameters are exchanged
  during the handshake, with each parameter having a type and value.

AAFP follows the TLS 1.3 pattern (client proposes, server accepts
subset) but uses CBOR maps instead of binary TLV encoding, for
consistency with the rest of the AAFP wire format.

**Wire Protocol Change**: Yes — defines the normative extension
format. No independent implementations exist.

**Backward Compatibility**: Breaks v0.1 MVP (which had no extension
negotiation). Justified because v0.1 is not v1-compatible.

**New Tradeoffs**:
- *Interoperability*: Dramatically improved. Extensions can now be
  negotiated.
- *Extensibility*: Established. New features can be added via
  extensions without protocol version changes.
- *Complexity*: Moderate increase. Implementations must track
  negotiated extensions and reject non-negotiated extension usage.
  This is standard practice (TLS requires it).
- *Security*: The negotiation protocol prevents extension stripping
  attacks (server must explicitly accept extensions; silent omission
  means not accepted).

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. The extension format is on the wire.
2. *Normative or informative?* — Normative (MUST/MUST NOT).
   Interoperability requires identical extension encoding and
   negotiation behavior.
3. *Expensive to change later?* — Yes. The extension format and
   negotiation protocol are foundational. Changing them requires a
   new protocol version.
4. *Adopt existing standard?* — Yes. The TLS 1.3 extension
   negotiation pattern (client proposes, server accepts subset) is
   the IETF standard. AAFP adapts it to CBOR, which is necessary
   for consistency with the AAFP wire format. This reduces
   maintenance by following a well-understood pattern.

---

### Amendment C4: Resolve RPC Params/Result Encoding Ambiguity

**Issue**: RPC `params` and `result` fields are `bstr` (opaque bytes),
but standard RPC methods pass structured data (AgentRecord, capability
names). Whether this is nested CBOR inside bstr is unspecified.

**Proposed Amendment**:

Change `params` and `result` from `bstr` to `any` (CBOR any type).
Define schemas for standard RPC methods' params and result.

**Affected RFCs**: RFC-0002 (Section 4.3, 4.4), RFC-0004 (Section 3.3
— RPC method schemas).

**Specific Changes to RFC-0002**:

Section 4.3 (RpcRequest):
```cbor
RpcRequest = {
    1: uint,       // "id": Correlation ID
    2: tstr,       // "method": Method name
    3: any,        // "params": Method parameters (CBOR any type)
                   // The structure depends on the method.
                   // See individual method definitions.
}
```

Section 4.4 (RpcResponse):
```cbor
RpcResponse = {
    1: uint,                    // "id": Matches request ID
    2: any / null,              // "result": Result data (null if error)
                                // Structure depends on the method.
    3: { ... } / null,          // "error": Error object (null if success)
}
```

Add a note to Section 4.3:
```
The `params` field (key 3) is of CBOR type `any`, allowing
structured data to be passed directly without nested encoding.
Each standard RPC method defines its params schema. Application-
defined methods define their own params schema.

For methods with no parameters, `params` MUST be `null` (CBOR null,
0xF6).
```

**Specific Changes to RFC-0004**:

Section 3.3 (`aafp.discovery.announce`):
```cbor
// Request params (key 3 of RpcRequest)
{
    1: AgentRecord,    // "record": The agent's AgentRecord
}

// Response result (key 2 of RpcResponse)
{
    1: [ *AgentRecord ],  // "peers": Known peers (may be empty)
}
```

Section 3.3 (`aafp.discovery.lookup`):
```cbor
// Request params
{
    1: tstr,          // "capability": Capability name
    2: uint / null,   // "limit": Max results (optional, default 10)
}

// Response result
{
    1: [ *AgentRecord ],  // "peers": Matching agents
}
```

Section 6.2 (`aafp.discovery.pex`):
```cbor
// Request params
{
    1: [ *bstr ],     // "known_peers": AgentIds the requester knows
    2: uint / null,   // "limit": Max new peers (optional)
}

// Response result
{
    1: [ *AgentRecord ],  // "peers": Peers the responder knows
}
```

**Rationale**: The `bstr` type forces implementers to guess whether
to nest CBOR inside the byte string. Using `any` allows structured
data to be passed directly, which is simpler and avoids a secondary
encoding layer. Each method's schema defines the exact structure.

**External Precedent**:
- JSON-RPC 2.0 uses `params` as a structured value (object or array),
  not a string-encoded blob.
- gRPC uses Protocol Buffers for structured params, not opaque bytes.
- COAP (RFC 7252) uses CBOR/JSON structured payloads for request
  parameters.

Using `any` (CBOR's equivalent of a generic value) follows the
JSON-RPC pattern adapted to CBOR.

**Wire Protocol Change**: Yes — changes the type of `params` and
`result` from `bstr` to `any`. No independent implementations exist.

**Backward Compatibility**: Breaks v0.1 MVP. Justified because v0.1
is not v1-compatible.

**New Tradeoffs**:
- *Interoperability*: Improved. Structured params are self-
  documenting in the schema.
- *Simplicity*: Improved. No nested encoding layer.
- *Validation*: Implementations can validate params against the
  method's schema at parse time, rather than decoding opaque bytes.
- *Extensibility*: Preserved. Application-defined methods can use
  any CBOR structure for params.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. The params type is on the wire.
2. *Normative or informative?* — Normative (MUST). The type must be
   consistent across implementations.
3. *Expensive to change later?* — Yes. Changing from `bstr` to `any`
   after implementations exist would break all RPC communication.
4. *Adopt existing standard?* — Yes. JSON-RPC 2.0's structured params
   pattern is widely understood. Adapting it to CBOR's `any` type
   is the natural fit. This reduces maintenance by following a
   proven pattern rather than inventing a nested-encoding scheme.

---

### Amendment C5: Add TLS Channel Binding to Handshake Transcript

**Issue**: The AAFP handshake is not cryptographically bound to the
TLS session, creating a relay attack vector. An attacker can
terminate TLS on both sides (using self-signed certificates under
TOFU) and relay AAFP handshake messages.

**Proposed Amendment**:

The TLS exporter value is included in the handshake transcript hash
(see Amendment C2). Both sides compute the TLS exporter after TLS
completion and include it in the transcript.

**Affected RFCs**: RFC-0002 (Section 5.6 — transcript hash includes
`tls_binding`), RFC-0003 (Section 7.1 — handshake flow diagram
updated), RFC-0001 (Section 9.3 — identity binding description
updated).

**Specific Changes to RFC-0002**:

Section 5.6 (Transcript Hash, added by Amendment C2) already includes
the TLS channel binding:
```
tls_binding = TLS-Exporter("aafp-channel-binding", "", 32)
h = SHA-256(tls_binding)
```

Add to Section 2.5 (Connection Lifecycle):
```
After TLS handshake completion and before sending the ClientHello,
the client MUST compute the TLS channel binding value:
    tls_binding = TLS-Exporter("aafp-channel-binding", "", 32)
The server MUST compute the same value after TLS completion.

The TLS exporter is defined in RFC 8446 Section 7.5. It produces
a keying material value bound to the TLS session. Including this
value in the AAFP transcript hash binds the AAFP session to the
specific TLS channel, preventing relay attacks.

If the TLS exporter is not available (e.g., the TLS implementation
does not support RFC 5705/RFC 8446 exporters), the implementation
MUST NOT proceed with the handshake. The connection MUST be closed
with error code 2006 (HANDSHAKE_FAILED).
```

**Specific Changes to RFC-0003**:

Section 7.1 (Full Handshake) — add after TLS handshake:
```
  |  QUIC connection + TLS handshake              |
  |  (X25519MLKEM768, ALPN=aafp/1)                |
  |<---------------------------------------------->|
  |                                               |
  |  Both sides compute:                          |
  |  tls_binding = TLS-Exporter(                  |
  |      "aafp-channel-binding", "", 32)          |
  |                                               |
  |  HANDSHAKE frame (ClientHello)                |
  |  ...                                          |
```

Section 8.1 (Identity Binding) — update:
```
The AAFP handshake binds the TLS session to the agents' ML-DSA-65
identities via the TLS channel binding. The TLS exporter value is
included in the transcript hash, which is signed by both agents.
Even if an attacker terminates TLS on both sides and relays AAFP
messages, the transcript hashes will differ because the TLS sessions
differ, causing signature verification failure.
```

**Specific Changes to RFC-0001**:

Section 9.3 (Identity Binding) — update:
```
The AAFP application-layer handshake binds the TLS session to the
agent's ML-DSA-65 identity via TLS channel binding. The TLS exporter
value (RFC 8446 Section 7.5) is included in the handshake transcript
hash. This prevents relay attacks: an attacker who terminates TLS
on both sides cannot relay AAFP handshake messages because the
transcript hashes will differ.
```

**Rationale**: Without channel binding, the AAFP handshake can be
relayed across two separate TLS sessions. The TLS exporter produces
a value unique to each TLS session; including it in the transcript
makes the AAFP signatures specific to that TLS session. An attacker
relaying messages between two TLS sessions will produce different
transcript hashes, causing signature verification failure.

**External Precedent**:
- Noise Protocol Framework (Section 11.2): "Parties can then sign
  the handshake hash... to get an authentication token which has a
  'channel binding' property: the token can't be used by the
  receiving party with a different session."
- TLS 1.3 (RFC 8446 Section 7.5): Defines the exporter API for
  channel binding: `TLS-Exporter(label, context_value, key_length)`.
- libp2p-noise: Binds peer identity to the Noise session by signing
  the static DH public key (which is session-bound via the Noise
  handshake hash).
- EAP channel binding (RFC 5056): Establishes the concept of
  binding application-layer authentication to lower-layer channels.

AAFP uses the TLS exporter (the standard channel binding mechanism
for TLS 1.3) rather than signing the DH key directly (as libp2p
does), because AAFP runs over QUIC/TLS rather than Noise. The TLS
exporter is the correct channel binding mechanism for TLS-based
protocols.

**Wire Protocol Change**: Yes — adds `tls_binding` to the transcript
hash computation. This changes signature values but not the frame
format (the transcript hash is not transmitted; only signatures
derived from it are).

**Backward Compatibility**: Breaks v0.1 MVP. Justified because v0.1
is not v1-compatible and no independent implementations exist.

**New Tradeoffs**:
- *Security*: Significantly improved. Relay attacks are prevented.
  This is the most important security improvement in the amendment
  set.
- *Latency*: Negligible. TLS exporter computation is ~1μs.
- *Complexity*: Slightly increased. Implementations must compute the
  TLS exporter. This is a standard TLS API (confirmed available in
  quinn via `Connection::export_keying_material()`).
- *Dependencies*: Implementations MUST use a TLS library that
  supports the exporter API. This is a reasonable requirement (all
  major TLS libraries support it).

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. The channel binding is part of the transcript hash,
   which determines signature values.
2. *Normative or informative?* — Normative (MUST). Without channel
   binding, the protocol has a known relay attack vulnerability.
3. *Expensive to change later?* — Yes. Changing the transcript
   construction (including removing the channel binding) invalidates
   all existing signatures. This is a one-way door.
4. *Adopt existing standard?* — Yes. The TLS exporter (RFC 8446
   §7.5) is the standard channel binding mechanism for TLS 1.3.
   Noise's `GetHandshakeHash()` (§11.2) is the equivalent for Noise.
   AAFP uses the TLS exporter because it runs over TLS. This reduces
   maintenance by using a well-defined, widely-implemented API
   rather than inventing a custom channel binding mechanism.

---

### Amendment C6: Update Stale Conformance Section

**Issue**: RFC-0001 Section 7.3 defines conformance for "AAFP v0.1"
(7 requirements) while RFC-0006 Section 8.1 defines conformance for
"AAFP version 1" (12 requirements). These are incompatible versions.

**Proposed Amendment**:

RFC-0001 Section 7.3 is replaced with a reference to RFC-0006 Section
8.1 as the normative conformance definition.

**Affected RFCs**: RFC-0001 (Section 7.3).

**Specific Changes to RFC-0001**:

Replace Section 7.3 with:
```
### 7.3 Implementation Conformance

The normative conformance requirements for AAFP version 1 are
defined in RFC-0006 Section 8.1. Implementations conforming to
this RFC series MUST satisfy those requirements.

The v0.1 MVP conformance requirements (defined in the pre-RFC
implementation) are obsolete and MUST NOT be used for conformance
claims.
```

**Rationale**: RFC-0001's conformance section is stale from the
pre-RFC era. It describes the MVP, not the standardized protocol.
An implementer reading RFC-0001 would conform to the wrong version.

**External Precedent**: IETF RFCs typically have a single normative
conformance section. When multiple documents exist, one is
designated as normative and others reference it. RFC-0006 (the
versioning and compatibility RFC) is the appropriate location for
conformance requirements.

**Wire Protocol Change**: No.

**Backward Compatibility**: No impact. This is a documentation
correction.

**New Tradeoffs**: None. This is a pure clarification.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* —
   Documentation requirement. No wire impact.
2. *Normative or informative?* — Normative (MUST). Conformance
   requirements must be unambiguous.
3. *Expensive to change later?* — No. This is a reference update.
4. *Adopt existing standard?* — N/A. This is an internal consistency
   fix.

---

## High-Severity Issues

---

### Amendment H1: Add Domain Separation to All Signatures

**Issue**: All AAFP signatures (handshake, AgentRecord, UCAN) are
computed over raw data with no domain separator prefix. This creates
a cross-protocol signature reuse risk.

**Proposed Amendment**:

All AAFP signature computations are prefixed with a domain separator
string. Different signature contexts use different separators.

**Affected RFCs**: RFC-0002 (Section 5.6 — handshake signatures),
RFC-0003 (Section 3.4 — AgentRecord signatures, Section 5.4 — UCAN
token signatures).

**Specific Changes**:

RFC-0002 Section 5.6 (added by Amendment C2) already includes the
domain separator `"aafp-v1-handshake"` in signature computations.

RFC-0003 Section 3.4 (AgentRecord Signature Computation) — update:
```
The signature is computed as follows:

1. Construct a CBOR map containing fields 1 through 7 (excluding
   field 8, the signature).
2. Encode the map using canonical CBOR (see RFC-0002 Section 8).
3. Compute the signature input:
   sig_input = "aafp-v1-record" || canonical_CBOR_bytes
4. Sign the signature input using ML-DSA-65 with the agent's
   secret key:
   signature = ML-DSA-65.Sign(secret_key, sig_input)
5. Place the signature in field 8.

The "aafp-v1-record" prefix is a domain separator that prevents
this signature from being valid in any other context.
```

RFC-0003 Section 5.4 (UCAN token) — add to signature computation:
```
The UCAN token signature (field 6) is computed over:
    sig_input = "aafp-v1-ucan" || canonical_CBOR(fields 1-5)
    signature = ML-DSA-65.Sign(secret_key, sig_input)
```

Add a new Section 3.5 to RFC-0003 (Domain Separation):
```
### 3.5 Domain Separation

All AAFP signatures are prefixed with a domain separator string
to prevent cross-protocol signature reuse. The domain separator
is prepended to the signature input before signing.

Defined domain separators:
- "aafp-v1-handshake": Handshake signatures (ClientHello,
  ServerHello, ClientFinished)
- "aafp-v1-record": AgentRecord signatures
- "aafp-v1-ucan": UCAN token signatures

Future signature contexts MUST define new domain separators
following the pattern "aafp-v<version>-<context>".

The domain separator is a UTF-8 string, NOT length-prefixed. The
signature input is the raw concatenation of the domain separator
bytes and the message bytes. This follows the Noise Protocol
Framework's approach of using raw concatenation for domain
separation (e.g., STATIC_KEY_DOMAIN in libp2p-noise).
```

**Rationale**: Without domain separation, a signature valid in one
AAFP context (e.g., AgentRecord) might be valid in another context
or in a different protocol that accepts ML-DSA-65 signatures over
CBOR data. Domain separation ensures signatures are only valid in
their intended context.

**External Precedent**:
- libp2p-noise: Uses "noise-libp2p-static-key:" as a domain
  separator for signatures over the static DH key. This prevents
  the signature from being valid in other Noise-based protocols.
- WireGuard: Uses "WireGuard v1 zx2c4 Jason@zx2c4.com" as the
  IDENTIFIER constant, hashed into the handshake hash for domain
  separation.
- TLS 1.3: Uses label strings in HKDF-Expand-Label (e.g.,
  "derived", "finished", "key") for domain separation within the
  key schedule.

**Wire Protocol Change**: Yes — changes signature computation. No
independent implementations exist.

**Backward Compatibility**: Breaks v0.1 MVP. Justified because v0.1
is not v1-compatible.

**New Tradeoffs**:
- *Security*: Improved. Cross-protocol signature reuse is prevented.
- *Interoperability*: All implementations must use the same domain
  separators. This is specified normatively.
- *Complexity*: Minimal. Prepending a string to the signature input
  is trivial.
- *Maintenance*: Domain separators are versioned ("aafp-v1-*"). New
  versions use new separators, allowing future protocol versions to
  distinguish signatures.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. Domain separators affect signature values, which are
   on the wire.
2. *Normative or informative?* — Normative (MUST). All implementations
   must use the same domain separators for signatures to verify.
3. *Expensive to change later?* — Yes. Changing domain separators
   invalidates all existing signatures. This is a one-way door.
4. *Adopt existing standard?* — Yes. Domain separation via prefix
   strings is established by libp2p-noise (STATIC_KEY_DOMAIN) and
   TLS 1.3 (HKDF labels). This reduces maintenance by following a
   proven cryptographic practice.

---

### Amendment H2: DoS Pre-Verification — Optional Deployment Profile

**Issue**: The server must perform expensive ML-DSA-65 signature
verification (~1ms) before rejecting invalid ClientHello messages.
WireGuard uses a cheap MAC (mac1) to reject invalid messages before
expensive crypto operations.

**Proposed Amendment**:

This amendment adds an OPTIONAL DoS pre-verification mechanism as a
deployment profile, NOT a mandatory protocol requirement. The core
protocol remains unchanged; deployments that face DoS threats MAY
enable pre-verification.

**Affected RFCs**: RFC-0002 (new Section 5.8 — DoS Mitigation
Profile), RFC-0005 (new error code 2009).

**Specific Changes to RFC-0002**:

Add new Section 5.8 (DoS Mitigation Profile):
```
### 5.8 DoS Mitigation Profile (Optional)

Deployments facing DoS threats (e.g., Internet-facing bootstrap
nodes) MAY implement a pre-verification mechanism to reject invalid
ClientHello messages before performing expensive ML-DSA-65 signature
verification.

This profile is OPTIONAL. Implementations conforming to AAFP v1 are
not required to implement it. Deployments that do not face DoS
threats (e.g., private networks, authenticated environments) MAY
omit it.

#### Mechanism

When the DoS mitigation profile is active, the ClientHello includes
an additional field (key 8) containing a receiver MAC:

ClientHello (with DoS profile) = {
    1: uint,       // protocol_version
    2: bstr,       // agent_id
    3: bstr,       // public_key
    4: bstr,       // nonce
    5: [ ... ],    // capabilities
    6: [ ... ],    // extensions
    7: bstr,       // signature
    8: bstr,       // receiver_mac (optional, DoS profile only)
}

The receiver_mac is computed as:
    mac_key = HKDF-SHA256(
        input = receiver_agent_id,
        info = "aafp-v1-dos-mac-key",
        length = 32)
    receiver_mac = HMAC-SHA256(
        key = mac_key,
        data = canonical_CBOR(ClientHello_without_signature_and_receiver_mac))

The server verifies the receiver_mac (a cheap HMAC operation, ~1μs)
before verifying the ML-DSA-65 signature (~1ms). If the MAC is
invalid, the server rejects the ClientHello with error code 2009
(RECEIVER_MAC_INVALID) without performing signature verification.

#### Negotiation

The DoS mitigation profile is negotiated via a handshake extension
(type 0x0001, "dos-mitigation"). The client includes this extension
in ClientHello.extensions if it supports the profile. The server
includes it in ServerHello.extensions if it requires the profile.

If the server requires the profile but the client did not propose
it, the server MUST send an ERROR frame with code 2005
(UNSUPPORTED_EXTENSIONS) and close the connection.

If neither side requires the profile, ClientHello field 8 (receiver_mac)
MAY be omitted. If field 8 is absent, the server proceeds directly
to signature verification.

#### Cookie Mechanism (Future)

A cookie-based mechanism (similar to WireGuard's mac2) for
proof-of-IP under load is deferred to a future RFC. The current
profile provides receiver-identity verification but not
source-address verification.
```

Add to RFC-0005 Section 3.3 (Authentication Errors):
```
| 2009 | RECEIVER_MAC_INVALID | DoS pre-verification MAC check failed. |
```

**Rationale**: DoS pre-verification is valuable for Internet-facing
deployments but may be unnecessary for private networks. Making it
an optional deployment profile (rather than a core requirement)
follows the principle of minimalism: the core protocol should not
mandate mechanisms that not all deployments need.

The user's guidance is correct: "whether it belongs in the core
protocol versus an optional deployment profile depends on your
threat model." AAFP serves both Internet-facing (bootstrap nodes)
and private (enterprise, research) deployments. The optional profile
allows each deployment to choose its DoS posture.

**External Precedent**:
- WireGuard: mac1 is always required, mac2 is required only under
  load. WireGuard's narrower scope (VPN tunnel) justifies always-on
  DoS protection. AAFP's broader scope (agent networking, including
  private deployments) justifies making it optional.
- TLS 1.3: Has anti-DoS discussions (RFC 8446 Section 8) but does
  not mandate a specific mechanism. TLS 1.3's HelloRetryRequest
  serves a similar purpose (forcing a round trip before expensive
  computation).
- QUIC: Address validation (RFC 9000 Section 8) is required but
  uses a connection-level mechanism, not a per-message MAC.

AAFP's optional profile is more conservative than WireGuard (which
mandates mac1) but more prescriptive than TLS 1.3 (which only
discusses DoS). This reflects AAFP's position between a focused VPN
protocol and a general-purpose transport.

**Wire Protocol Change**: Yes — adds an optional field to ClientHello
and a new error code. The field is optional; implementations that
don't use the DoS profile are unaffected.

**Backward Compatibility**: Does not break compatibility. The
receiver_mac field (key 8) is optional. Implementations that don't
recognize it will ignore it (per RFC-0006 Section 6.1: "Unknown CBOR
map fields: Skip (ignore)"). The DoS profile is negotiated via
extensions, so both sides must agree before using it.

**New Tradeoffs**:
- *Security*: Improved for deployments that enable the profile.
  Unchanged for deployments that don't.
- *Latency*: Negligible. HMAC-SHA256 is ~1μs vs ~1ms for ML-DSA-65
  verification.
- *Complexity*: Moderate. Deployments that enable the profile must
  implement HMAC verification and the extension negotiation.
- *Flexibility*: Deployments can choose their DoS posture based on
  their threat model.
- *Wire format*: The optional field adds 32 bytes to ClientHello
  when the profile is active. When inactive, no overhead.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* —
   Implementation recommendation (deployment profile). The core
   protocol does not require it. Deployments MAY enable it.
2. *Normative or informative?* — Mixed. The mechanism specification
   (how to compute the MAC, how to negotiate) is normative (MUST)
   for implementations that choose to implement the profile. The
   decision to implement the profile is informative (MAY).
3. *Expensive to change later?* — No. The profile is optional and
   negotiated. Adding it doesn't affect existing implementations.
   Removing it doesn't affect implementations that don't use it.
   This is a two-way door.
4. *Adopt existing standard?* — Partially. WireGuard's mac1 pattern
   is the inspiration, but AAFP adapts it to an optional profile
   rather than a mandatory mechanism, reflecting AAFP's broader
   deployment scope. The HMAC-SHA256 + HKDF pattern is standard
   (TLS, Noise, WireGuard all use it).

---

### Amendment H3: Fix Error Code Misuse (2001 vs 2007)

**Issue**: RFC-0003 Section 2.1 uses error code 2001 (INVALID_SIGNATURE)
for AgentId mismatch, but RFC-0005 defines 2007 (INVALID_AGENT_ID)
for this purpose.

**Proposed Amendment**:

RFC-0003 Section 2.1 is updated to use error code 2007 for AgentId
mismatch and 2001 for actual signature verification failures.

**Affected RFCs**: RFC-0003 (Section 2.1).

**Specific Changes to RFC-0003**:

Section 2.1 — update:
```
Implementations MUST verify that a received AgentId matches
`SHA-256(received_public_key)` during the handshake. If the
verification fails, the implementation MUST reject the handshake
with error code `2007` (INVALID_AGENT_ID).

If the ML-DSA-65 signature verification fails (the signature does
not validate against the public key), the implementation MUST
reject the handshake with error code `2001` (INVALID_SIGNATURE).
```

**Rationale**: AgentId mismatch is an identity binding failure, not
a signature failure. Using the correct error code enables clients to
distinguish between "the agent is misrepresenting its identity" and
"the signature is invalid" — these require different responses.

**External Precedent**: TLS 1.3 defines distinct alert types for
different failure modes (e.g., `bad_certificate` vs
`certificate_revoked` vs `certificate_expired`). QUIC defines
distinct transport error codes for different protocol violations.

**Wire Protocol Change**: No (error code semantics only).

**Backward Compatibility**: No impact. This is a clarification.

**New Tradeoffs**: None. This is a correctness fix.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. Error codes are on the wire.
2. *Normative or informative?* — Normative (MUST). Correct error
   codes are required for interoperability.
3. *Expensive to change later?* — No. Error code assignments are
   permanent, but using the correct one now is trivial.
4. *Adopt existing standard?* — Yes. Distinct error codes for
   distinct failure modes is standard IETF practice (TLS, QUIC).

---

### Amendment H4: Add expires_at to Handshake Messages

**Issue**: ClientHello and ServerHello don't include `expires_at`,
so the peer cannot verify identity expiry without an AgentRecord from
discovery.

**Proposed Amendment**:

Add `expires_at` (uint) to ClientHello and ServerHello.

**Affected RFCs**: RFC-0002 (Sections 5.3, 5.4), RFC-0003 (Section
7.2 — verification steps).

**Specific Changes to RFC-0002**:

ClientHello — add field 8 (renumbering signature to 9, or using 8
for expires_at and keeping signature at 7 — let me think about this
carefully).

Actually, with Amendment C1, ClientHello already has:
```
1: protocol_version
2: agent_id
3: public_key
4: nonce
5: capabilities
6: extensions
7: signature
```

And with Amendment H2 (optional DoS profile), field 8 is
`receiver_mac`. So `expires_at` should be field 9.

But wait — `expires_at` is more fundamental than `receiver_mac`
(which is optional). Let me assign `expires_at` to field 8 and
`receiver_mac` to field 9.

Updated ClientHello:
```cbor
ClientHello = {
    1: uint,       // protocol_version
    2: bstr,       // agent_id
    3: bstr,       // public_key
    4: bstr,       // nonce
    5: [ *CapabilityDescriptor ],  // capabilities
    6: [ *ExtensionEntry ],        // extensions
    7: bstr,       // signature
    8: uint,       // expires_at: Unix timestamp (seconds)
    9: bstr,       // receiver_mac (optional, DoS profile only)
}
```

Updated ServerHello:
```cbor
ServerHello = {
    1: uint,       // protocol_version
    2: bstr,       // agent_id
    3: bstr,       // public_key
    4: bstr,       // nonce
    5: [ *CapabilityDescriptor ],  // capabilities
    6: [ *ExtensionEntry ],        // extensions
    7: bstr,       // session_id
    8: bstr,       // signature
    9: uint,       // expires_at: Unix timestamp (seconds)
}
```

**Specific Changes to RFC-0003**:

Section 7.2 (Authentication Verification Steps) — add:
```
**Client verifies ServerHello:**
...
6. `expires_at > current_time`. If expired, reject with error
   code 2002 (IDENTITY_EXPIRED).

**Server verifies ClientHello:**
...
6. `expires_at > current_time`. If expired, reject with error
   code 2002 (IDENTITY_EXPIRED).
```

**Rationale**: Without `expires_at` in the handshake, the peer must
obtain the AgentRecord from discovery to check expiry. If the peer
doesn't have the AgentRecord, it cannot verify that the identity
hasn't expired. Including `expires_at` in the handshake makes the
handshake self-contained for expiry verification.

**External Precedent**:
- X.509 certificates include `notBefore` and `notAfter` fields.
- JWT tokens include `exp` (expiration time) claim.
- AgentRecord (RFC-0003 Section 3.2) already includes `expires_at`.

**Wire Protocol Change**: Yes — adds a field to ClientHello and
ServerHello. No independent implementations exist.

**Backward Compatibility**: Breaks v0.1 MVP. Justified because v0.1
is not v1-compatible.

**New Tradeoffs**:
- *Security*: Improved. Peers can verify expiry without discovery
  lookup.
- *Bandwidth*: +8 bytes per handshake message (uint encoding of
  timestamp). Negligible compared to the ~10KB handshake.
- *Complexity*: Minimal. One additional field to verify.
- *Consistency*: The `expires_at` in the handshake SHOULD match the
  `expires_at` in the agent's AgentRecord. If they differ, the
  handshake value takes precedence for the session (it is the
  agent's current claim).

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. The field is on the wire.
2. *Normative or informative?* — Normative (MUST). The field is
   required for expiry verification.
3. *Expensive to change later?* — Yes. Adding fields after
   implementations exist requires a new protocol version (though CBOR
   schema evolution allows adding optional fields, making this field
   required would break implementations that don't include it).
4. *Adopt existing standard?* — Yes. X.509 certificates and JWT
   tokens both include expiration timestamps. This is a well-
   established pattern for identity documents.

---

### Amendment H5: Fix FRAME_TOO_LARGE Fatal/Stream Contradiction

**Issue**: RFC-0002 Section 3.4 says "close the stream" for
FRAME_TOO_LARGE, but RFC-0005 Section 4.4 says 8001 is always fatal
(close the connection).

**Proposed Amendment**:

Remove 8001 from the "always fatal" list in RFC-0005. The sender MAY
set the fatal flag based on whether the oversized frame indicates a
connection-level or stream-level problem.

**Affected RFCs**: RFC-0005 (Section 4.4), RFC-0002 (Section 3.4 —
clarify behavior).

**Specific Changes to RFC-0005**:

Section 4.4 — update the "always fatal" list:
```
The following error codes are ALWAYS fatal:

- All 2xxx (Authentication) errors
- 8004 (UNKNOWN_CRITICAL_FRAME_TYPE)
- 8005 (UNKNOWN_CRITICAL_EXTENSION)
- 8006 (INVALID_VERSION)
- 8009 (PROTOCOL_VIOLATION)

Error code 8001 (FRAME_TOO_LARGE) is non-fatal by default. The
sender MAY set the fatal flag to true if the oversized frame
indicates a connection-level protocol violation (e.g., the peer
repeatedly sends oversized frames despite prior errors).
```

**Specific Changes to RFC-0002**:

Section 3.4 — update:
```
The maximum payload size is 1 MiB (1,048,576 bytes). Implementations
MUST reject frames with payloads larger than this limit by sending
an ERROR frame (see RFC-0005) with error code `8001`
(FRAME_TOO_LARGE) and closing the stream. The error frame's fatal
flag SHOULD be false (non-fatal), allowing the connection to
continue for other streams. If the peer repeatedly sends oversized
frames, the implementation MAY set the fatal flag to true and close
the connection.
```

**Rationale**: A single oversized frame on one stream shouldn't kill
the entire connection. Other streams may have valid data. Making 8001
non-fatal by default allows graceful recovery.

**External Precedent**:
- QUIC (RFC 9000 Section 11.2): Distinguishes connection errors from
  stream errors. Stream errors close only the affected stream.
- TLS 1.3: Distinguishes fatal alerts from warnings (though TLS 1.3
  removes most warnings).

**Wire Protocol Change**: No (error semantics clarification).

**Backward Compatibility**: No impact. This is a clarification.

**New Tradeoffs**:
- *Robustness*: Improved. Single oversized frames don't kill
  connections.
- *DoS*: Slightly increased risk. An attacker can send oversized
  frames on many streams without killing the connection. Mitigated
  by the ability to set fatal=true for repeated violations.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. Error handling semantics affect connection behavior.
2. *Normative or informative?* — Normative (MUST/SHOULD). The
   default fatal behavior must be consistent across implementations.
3. *Expensive to change later?* — No. Error handling semantics can
   be clarified without wire format changes.
4. *Adopt existing standard?* — Yes. QUIC's stream error vs
   connection error distinction is the standard approach.

---

### Amendment H6: Clarify PING/PONG Stream Semantics

**Issue**: PING/PONG frames are described as keepalive probes but
the "same stream" requirement is confusing — it's unclear whether
PING is connection-level or stream-level.

**Proposed Amendment**:

Clarify that PING/PONG MAY be sent on any open stream (including
stream 0) and are used for application-layer keepalive. Note that
QUIC provides its own transport-level keepalive; AAFP PING/PONG is
for application-layer liveness.

**Affected RFCs**: RFC-0002 (Sections 4.7, 4.8).

**Specific Changes to RFC-0002**:

Section 4.7 (PING Frame) — update:
```
### 4.7 PING Frame (0x07)

    FrameType = 0x07
    Payload:  Empty (0 bytes)

A PING frame is an application-layer keepalive probe. The receiver
MUST respond with a PONG frame on the same stream.

PING frames MAY be sent on any open stream, including stream 0
(the handshake stream, which remains open after the handshake
completes). Sending PING on stream 0 is RECOMMENDED for
connection-level keepalive, as it does not require opening a new
stream.

Note: QUIC provides its own transport-level keepalive mechanism
(via idle timeout and PING frames at the QUIC layer). AAFP PING/
PONG frames are for application-layer liveness checks and are
distinct from QUIC's keepalive. Implementations MAY use either or
both mechanisms.
```

Section 4.8 (PONG Frame) — update:
```
### 4.8 PONG Frame (0x08)

    FrameType = 0x08
    Payload:  Empty (0 bytes)

A PONG frame is the response to a PING frame. It MUST be sent on
the same stream as the PING frame.
```

**Rationale**: The "same stream" requirement was confusing because
it wasn't clear which stream a keepalive PING should use. Clarifying
that PING may use any open stream (with stream 0 recommended for
connection-level keepalive) resolves the ambiguity.

**External Precedent**:
- QUIC PING frames (RFC 9000 Section 19.2): Can be sent in any
  packet, used for keepalive/liveness.
- HTTP/2 PING frames (RFC 7540 Section 6.7): Connection-level, not
  stream-level, with an opaque payload for correlation.

**Wire Protocol Change**: No (clarification only).

**Backward Compatibility**: No impact.

**New Tradeoffs**: None. This is a clarification.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement (MUST respond to PING with PONG). The stream choice
   is a recommendation (MAY use any stream, RECOMMENDED stream 0).
2. *Normative or informative?* — Mixed. The PONG response is
   normative (MUST). The stream choice is informative (RECOMMENDED).
3. *Expensive to change later?* — No. PING/PONG semantics can be
   clarified without wire format changes.
4. *Adopt existing standard?* — Yes. HTTP/2 PING is connection-level;
   QUIC PING is packet-level. AAFP's "any stream" approach is a
   generalization that accommodates both use cases.

---

### Amendment H7: Signature Computation Ambiguity (Resolved by C1)

**Issue**: Signature computation is ambiguous because it's unclear
whether signatures are over integer-keyed or string-keyed CBOR maps.

**Resolution**: This issue is fully resolved by Amendment C1
(standardizing on integer keys) and Amendment C2 (defining the
transcript hash). The signature computation now explicitly states
that it is over "canonical CBOR encoding of the map using integer
keys as specified in the schema."

No separate amendment is needed.

**Architecture Questions**: See C1 and C2.

---

### Amendment H8: Add Signature Algorithm Agility

**Issue**: The protocol mandates ML-DSA-65 for all signatures with no
mechanism to negotiate alternative algorithms. If ML-DSA-65 is broken
or deprecated, all agent identities become invalid.

**Proposed Amendment**:

Add a `key_algorithm` field (uint) to ClientHello and ServerHello.
Define a key algorithm registry. v1 implementations MUST support
ML-DSA-65 (algorithm 1) and MAY support others.

**Affected RFCs**: RFC-0002 (Sections 5.3, 5.4 — add field),
RFC-0003 (Section 2.3 — key algorithm registry), RFC-0006 (new
registry).

**Specific Changes to RFC-0002**:

ClientHello — add field 10 (key_algorithm):
```cbor
ClientHello = {
    1: uint,       // protocol_version
    2: bstr,       // agent_id
    3: bstr,       // public_key
    4: bstr,       // nonce
    5: [ ... ],    // capabilities
    6: [ ... ],    // extensions
    7: bstr,       // signature
    8: uint,       // expires_at
    9: bstr,       // receiver_mac (optional, DoS profile)
    10: uint,      // key_algorithm (see RFC-0003 Section 2.3)
}
```

ServerHello — add field 10 (key_algorithm):
```cbor
ServerHello = {
    1: uint,       // protocol_version
    2: bstr,       // agent_id
    3: bstr,       // public_key
    4: bstr,       // nonce
    5: [ ... ],    // capabilities
    6: [ ... ],    // extensions
    7: bstr,       // session_id
    8: bstr,       // signature
    9: uint,       // expires_at
    10: uint,      // key_algorithm
}
```

**Specific Changes to RFC-0003**:

Section 2.3 — add key algorithm registry:
```
### 2.3 Key Algorithm Registry

Each agent's public key is associated with a key algorithm that
identifies the signature scheme. The key algorithm is carried in
the handshake (ClientHello/ServerHello field 10) and in the
AgentRecord (new field 9).

Key Algorithm Registry:
| Code | Name       | Public Key Size | Signature Size | Reference |
|------|------------|-----------------|----------------|-----------|
| 1    | ML-DSA-65  | 1952 bytes      | 3309 bytes     | FIPS 204  |
| 2    | ML-DSA-44  | 1312 bytes      | 2420 bytes     | FIPS 204  |
| 3    | ML-DSA-87  | 2592 bytes      | 4627 bytes     | FIPS 204  |
| 4    | SLH-DSA-128s | 32 bytes      | 7856 bytes     | FIPS 205  |
| 5-255| Reserved   | —               | —              | —         |

v1 implementations MUST support ML-DSA-65 (algorithm 1).
Implementations MAY support additional algorithms.

The AgentId derivation is the same for all algorithms:
    AgentId = SHA-256(public_key)
This ensures AgentId stability across algorithm changes (though a
key rotation to a new algorithm produces a new AgentId, since the
public key changes).

AgentRecord — add field 9:
```
AgentRecord = {
    1: tstr,          // record_type
    2: bstr,          // agent_id
    3: bstr,          // public_key
    4: [ ... ],       // capabilities
    5: [ ... ],       // endpoints
    6: uint,          // created_at
    7: uint,          // expires_at
    8: bstr,          // signature
    9: uint,          // key_algorithm (NEW)
}
```

The signature (field 8) is computed over fields 1–7 and 9 (excluding
field 8). The key_algorithm field is included in the signature to
prevent algorithm substitution attacks.
```

**Specific Changes to RFC-0006**:

Add to IANA Considerations:
```
- **AAFP Key Algorithm Registry**: Values 1–255 (see RFC-0003
  Section 2.3)
```

**Rationale**: Cryptographic agility is a key lesson from the
deprecation of SHA-1 and RSA. Without algorithm negotiation, AAFP
cannot migrate to new signature schemes if ML-DSA-65 is compromised
or deprecated. Adding the `key_algorithm` field now (before v1
freeze) is cheap; adding it later requires a new protocol version.

The user's guidance is relevant: "A self-describing identifier (such
as a multihash or another algorithm-agile encoding) is worth
considering for cryptographic agility." The `key_algorithm` field
provides algorithm agility for signatures. AgentId derivation remains
SHA-256 (which is quantum-resistant and not tied to the signature
algorithm), so the identifier is stable even if the signature
algorithm changes.

**External Precedent**:
- TLS 1.3 (RFC 8446 Section 4.2.3): `signature_algorithms` extension
  negotiates signature algorithms.
- JWT (RFC 7519): `alg` header parameter identifies the signature
  algorithm.
- COSE (RFC 8152): Algorithm identifiers are carried in message
  headers.

**Wire Protocol Change**: Yes — adds a field to ClientHello,
ServerHello, and AgentRecord. No independent implementations exist.

**Backward Compatibility**: Breaks v0.1 MVP. Justified because v0.1
is not v1-compatible.

**New Tradeoffs**:
- *Cryptographic agility*: Significantly improved. New algorithms
  can be added without protocol version changes.
- *Bandwidth*: +1–2 bytes per handshake message (uint encoding of
  algorithm code). Negligible.
- *Complexity*: Moderate. Implementations must support at least
  ML-DSA-65 and verify the algorithm field. Supporting multiple
  algorithms adds complexity but is optional.
- *Security*: The key_algorithm field is included in the signature
  to prevent algorithm substitution attacks (an attacker can't
  change the algorithm field without invalidating the signature).
- *AgentId stability*: AgentId = SHA-256(public_key) is independent
  of the algorithm. Changing algorithms produces a new AgentId
  (because the public key changes), but the derivation method is
  stable.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* — Protocol
   requirement. The algorithm field is on the wire.
2. *Normative or informative?* — Normative (MUST support algorithm 1;
   MAY support others). The field itself is required.
3. *Expensive to change later?* — Yes. Adding the field after
   implementations exist requires a new protocol version (making a
   new required field). Adding it now is cheap. This is a one-way
   door that should be open before v1.
4. *Adopt existing standard?* — Yes. TLS 1.3's `signature_algorithms`
   extension and JWT's `alg` header are the standard patterns for
   algorithm identification. AAFP's approach (a uint field rather
   than an extension) is simpler and suitable for a protocol with a
   small number of algorithms.

---

### Amendment H9: Define Extension Negotiation Protocol (Resolved by C3)

**Issue**: RFC-0002 Section 6.3 describes extension types (optional,
negotiated, mandatory) but doesn't specify the negotiation protocol.

**Resolution**: This issue is fully resolved by Amendment C3, which
defines the handshake extension format and the negotiation protocol
(client proposes in ClientHello, server accepts subset in
ServerHello, non-negotiated extensions cause errors).

No separate amendment is needed.

**Architecture Questions**: See C3.

---

### Amendment H10: Document Revocation Risk and Recommend Short Expiry

**Issue**: No revocation mechanism exists in v1. A compromised
ML-DSA-65 key remains valid until the AgentRecord's `expires_at`.

**Proposed Amendment**:

This is a documentation amendment. RFC-0003 Section 8.4 is expanded
to document the risk, recommend short expiry times, and outline the
future revocation mechanism design.

**Affected RFCs**: RFC-0003 (Section 8.4).

**Specific Changes to RFC-0003**:

Section 8.4 — expand:
```
### 8.4 Key Compromise and Revocation

If an agent's ML-DSA-65 secret key is compromised:

1. The attacker can impersonate the agent.
2. The attacker can sign AgentRecords and UCAN tokens.
3. Existing sessions are NOT compromised (they use TLS-derived
   session keys, not ML-DSA-65 keys).

Compromised agents MUST rotate their key pair and publish a new
AgentRecord with a new AgentId.

#### Revocation (v1 Limitation)

AAFP v1 does NOT provide a revocation mechanism. A compromised key
remains valid until the AgentRecord's `expires_at` timestamp. This
is a known limitation.

To mitigate the impact of key compromise:

1. Implementations SHOULD use short AgentRecord expiry times.
   RECOMMENDED maximum: 30 days (2,592,000 seconds).
2. Implementations SHOULD renew AgentRecords frequently (e.g.,
   every 7 days) to keep the expiry window short.
3. The `expires_at` field in the handshake (Amendment H4) allows
   peers to verify expiry without discovery lookup.
4. Applications SHOULD implement their own revocation checking
   (e.g., a revocation list published out-of-band) if the threat
   model requires it.

#### Future Revocation Mechanism

A future RFC will specify a revocation mechanism. The design will
consider:

- **Revocation lists**: Signed lists of revoked AgentIds, published
  to bootstrap nodes or a dedicated service.
- **Short-lived records**: AgentRecords with very short expiry
  (e.g., 1 hour), requiring frequent renewal. Revocation is
  achieved by not renewing.
- **Delegation-based revocation**: A trusted authority signs
  revocation statements. This requires a trust model that AAFP v1
  does not define.

The `key_algorithm` field (Amendment H8) and the extension mechanism
(Amendment C3) provide the foundation for future revocation
extensions.
```

**Rationale**: Revocation is a complex topic that requires careful
design. Deferring it to a future RFC is appropriate for v1, but the
risk must be documented and mitigations recommended. Short expiry
times are the primary mitigation.

**External Precedent**:
- X.509: CRLs (Certificate Revocation Lists) and OCSP (Online
  Certificate Status Protocol) are complex and widely criticized.
  Short-lived certificates are increasingly preferred (e.g,
  Let's Encrypt's 90-day certificates).
- WireGuard: No revocation mechanism. Relies on key rotation.
- libp2p: No built-in revocation. Relies on PeerId rotation.

**Wire Protocol Change**: No.

**Backward Compatibility**: No impact. This is documentation.

**New Tradeoffs**:
- *Security*: Documented risk with mitigations. Not resolved, but
  the limitation is explicit.
- *Operational*: Short expiry times require more frequent AgentRecord
  renewal, increasing operational overhead.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* —
   Implementation recommendation. The short expiry is a SHOULD, not
   a MUST. The protocol does not enforce expiry limits.
2. *Normative or informative?* — Informative (SHOULD). The
   recommendation is guidance, not a protocol requirement.
3. *Expensive to change later?* — No. Adding a revocation mechanism
   in a future RFC does not change the v1 wire format (it would use
   extensions or a new frame type).
4. *Adopt existing standard?* — Partially. The short-lived
   certificate pattern (Let's Encrypt) is the modern approach to
  revocation. AAFP recommends this pattern. A full revocation
   mechanism would need to be designed based on AAFP's specific
   requirements.

---

### Amendment H11: Define Fingerprint Format for Out-of-Band Verification

**Issue**: RFC-0003 Section 8.3 says implementations SHOULD provide
a mechanism for out-of-band identity verification but doesn't define
a specific format.

**Proposed Amendment**:

Define a fingerprint format for AgentId verification, similar to SSH
fingerprints or Signal safety numbers.

**Affected RFCs**: RFC-0003 (Section 8.3, new Section 2.5).

**Specific Changes to RFC-0003**:

Add Section 2.5 (AgentId Fingerprint):
```
### 2.5 AgentId Fingerprint

For out-of-band identity verification, implementations SHOULD
display AgentIds in a human-readable fingerprint format:

    AAFP-<base32(first_16_bytes_of_AgentId)>-<CRC32>

Where:
- `base32` is RFC 4648 base32 encoding (no padding, uppercase)
- `first_16_bytes_of_AgentId` is the first 16 bytes of the 32-byte
  AgentId
- `CRC32` is a 4-character hex CRC-32 checksum of the first 16
  bytes, for typo detection

Example:
    AgentId = 0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
    Fingerprint = AAFP-A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2-3E7F8A9B

The fingerprint is for human verification only (e.g., comparing
displayed fingerprints between agents). It is NOT used for protocol-
level lookup or comparison. The full 32-byte AgentId is used for all
protocol operations.

Implementations SHOULD display the fingerprint when a new agent
connection is established and provide an API for applications to
retrieve and compare fingerprints.
```

Section 8.3 — update:
```
Implementations SHOULD provide a mechanism for users to verify
agent identities out-of-band using the fingerprint format defined
in Section 2.5. Users compare fingerprints through a trusted
channel (e.g., voice, QR code, or pre-shared configuration) to
detect man-in-the-middle attacks on first connection.
```

**Rationale**: Without a concrete fingerprint format, the TOFU
mitigation is aspirational. Users won't manually compare 64-character
hex strings. A shorter, checksum-protected format makes verification
practical.

**External Precedent**:
- SSH: Fingerprint format `SHA256:base64(hash)` for host key
  verification.
- Signal: Safety numbers (60-digit decimal) for identity verification.
- PGP: Long fingerprint format (40 hex chars) and short format
  (8 hex chars).

AAFP's format is shorter than Signal's safety number and longer than
PGP's short format, providing a balance between security and
usability.

**Wire Protocol Change**: No (display format only).

**Backward Compatibility**: No impact.

**New Tradeoffs**:
- *Usability*: Improved. Fingerprints are short and checksum-
  protected.
- *Security*: The fingerprint uses only the first 16 bytes of the
  AgentId (64-bit collision resistance for display purposes). This
  is sufficient for human verification — the full 32-byte AgentId
  is used for all protocol operations.
- *Complexity*: Minimal. Base32 encoding and CRC-32 are trivial to
  implement.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* —
   Implementation recommendation. The fingerprint format is for
   display, not wire protocol.
2. *Normative or informative?* — Informative (SHOULD).
   Implementations SHOULD display fingerprints but are not required
   to. The format itself is normative (if displayed, it MUST use
   this format) to ensure consistency.
3. *Expensive to change later?* — No. The fingerprint format can be
   changed without wire protocol impact. However, changing it after
   users are familiar with the format would cause confusion.
4. *Adopt existing standard?* — Yes. SSH fingerprints and Signal
   safety numbers are the established patterns. AAFP's format is a
   hybrid (base32 like SSH, checksum like Signal) adapted to
   AgentId's structure.

---

### Amendment H12: Rate-Limit Bootstrap Discovery Requests

**Issue**: Bootstrap nodes respond to `aafp.discovery.lookup` with
up to 10 AgentRecords (~50-70KB response for ~100-byte request),
creating a ~500x amplification factor.

**Proposed Amendment**:

RFC-0004 Section 3.4 is updated to specify rate limiting and
authentication requirements for bootstrap nodes.

**Affected RFCs**: RFC-0004 (Section 3.4).

**Specific Changes to RFC-0004**:

Section 3.4 — update:
```
### 3.4 Bootstrap Node Requirements

- Bootstrap nodes MUST accept incoming connections.
- Bootstrap nodes MUST store AgentRecords received via `announce`.
- Bootstrap nodes MUST respond to `lookup` requests with matching
  records.
- Bootstrap nodes SHOULD evict expired records.
- Bootstrap nodes SHOULD limit the number of records stored to
  prevent memory exhaustion (RECOMMENDED: 100,000 records).
- Bootstrap nodes MUST rate-limit discovery requests per connection:
  - `announce`: Maximum 1 request per 60 seconds per connection.
  - `lookup`: Maximum 10 requests per 60 seconds per connection.
  - `pex`: Maximum 1 request per 60 seconds per connection.
- Bootstrap nodes MUST verify the requester's AgentRecord signature
  before responding to `lookup` requests. If the requester's
  AgentRecord is invalid or expired, the bootstrap node MUST reject
  the request with error code 4003 (RECORD_INVALID) or 4004
  (RECORD_EXPIRED).
- Bootstrap nodes MAY reject requests from agents that have not
  announced their own AgentRecord.
- Bootstrap nodes MAY rate-limit at the IP level for connections
  that exceed per-connection limits.
- The default `limit` parameter for `lookup` is reduced from 10 to
  5 for unauthenticated requests (requests from agents without a
  valid AgentRecord).
```

**Rationale**: Bootstrap nodes are shared infrastructure vulnerable
to resource exhaustion. Rate limiting and authentication requirements
protect them from abuse. QUIC's address validation prevents source
address spoofing, but malicious clients can still open many
connections and issue expensive requests.

**External Precedent**:
- DNS resolvers: Rate-limit queries per source IP (Response Rate
  Limiting, RFC 5752).
- STUN servers: Rate-limit requests per source IP.
- DHT bootstrap nodes (libp2p, BitTorrent): Implement per-IP rate
  limiting.

**Wire Protocol Change**: No (implementation requirements).

**Backward Compatibility**: No impact. These are server-side
requirements that don't affect the wire format.

**New Tradeoffs**:
- *Security*: Improved. Bootstrap nodes are protected from resource
  exhaustion.
- *Scalability*: The 100,000 record limit (increased from 10,000)
  supports larger networks while remaining manageable (100K × 6KB
  = 600MB).
- *Latency*: Rate limiting may delay legitimate requests from
  clients that exceed limits. This is acceptable for bootstrap
  nodes, which are not on the critical path for established
  connections.
- *Authentication*: Requiring AgentRecord verification for lookups
  adds a signature verification (~1ms) per lookup request. This is
  acceptable given the 10 requests/60 second rate limit.

**Architecture Questions**:

1. *Protocol requirement or implementation recommendation?* —
   Implementation requirement for bootstrap nodes. Non-bootstrap
   nodes are unaffected.
2. *Normative or informative?* — Normative (MUST for rate limiting
   and authentication; SHOULD for record limits). Bootstrap nodes
   are shared infrastructure and MUST implement protections.
3. *Expensive to change later?* — No. Rate limits can be adjusted
   without wire protocol changes.
4. *Adopt existing standard?* — Yes. Rate limiting per source is
   standard practice for public infrastructure (DNS RRL, STUN
   rate limiting). AAFP adapts it to per-connection rate limiting,
   which is more precise (QUIC connections are authenticated via
   TLS, unlike UDP source addresses).

---

## Cross-RFC Consistency Pass

After all amendments, a consistency check was performed across all
RFCs. The following items were verified:

### 1. CBOR Key Convention Consistency

**Status**: CONSISTENT after Amendment C1.

All CBOR structures across all RFCs now use integer keys:
- RFC-0002: RpcRequest, RpcResponse, CloseMessage, ErrorMessage,
  ClientHello, ServerHello, ClientFinished (all integer-keyed per C1)
- RFC-0003: AgentRecord, CapabilityDescriptor, UcanToken (already
  integer-keyed)
- RFC-0004: RPC method params and results (integer-keyed per C4)
- RFC-0005: RpcResponse error object (already integer-keyed, confirmed
  consistent with RFC-0002's updated RpcResponse)

### 2. Handshake Field Numbering Consistency

**Status**: CONSISTENT after Amendments C1, C3, H2, H4, H8.

ClientHello fields:
```
1: protocol_version
2: agent_id
3: public_key
4: nonce
5: capabilities
6: extensions (ExtensionEntry array, per C3)
7: signature
8: expires_at (per H4)
9: receiver_mac (optional, per H2)
10: key_algorithm (per H8)
```

ServerHello fields:
```
1: protocol_version
2: agent_id
3: public_key
4: nonce
5: capabilities
6: extensions (ExtensionEntry array, per C3)
7: session_id
8: signature
9: expires_at (per H4)
10: key_algorithm (per H8)
```

ClientFinished fields:
```
1: session_id
2: signature
```

Note: ClientHello field 9 (receiver_mac) is optional. When absent,
it is omitted from the CBOR map (not encoded as null). This is valid
per CBOR map semantics (maps need not contain all possible keys).
The signature (field 7) is computed over the map excluding the
signature field. The receiver_mac (if present) IS included in the
signature input (it is not excluded). Wait — this is wrong. The
receiver_mac should be excluded from the signature input because
the signature is verified before the receiver_mac (the receiver_mac
is a pre-verification mechanism). Let me correct this.

**Correction**: The signature input excludes both the signature
field (7) and the receiver_mac field (9). The transcript hash
definition (Amendment C2) must be updated:

```
canonical_CBOR(ClientHello_without_signature_and_receiver_mac)
```

This means the ClientHello map for signature purposes contains
fields 1-6, 8, 10 (excluding 7=signature and 9=receiver_mac). The
CBOR encoding of this subset is used for the transcript hash.

This is consistent because:
- The signature can't include itself (circular).
- The receiver_mac is verified before the signature (it's a DoS
  pre-filter), so it can't depend on the signature.
- The receiver_mac is computed over the same data as the signature
  (ClientHello without signature and receiver_mac), so both cover
  the same fields.

**Updated consistency**: CONSISTENT with this correction.

### 3. Transcript Hash Consistency

**Status**: CONSISTENT after Amendments C2, C5, H1.

The transcript hash is defined in RFC-0002 Section 5.6:
```
h = SHA-256(tls_binding)
h = SHA-256(h || canonical_CBOR(ClientHello_without_sig_and_mac))
h = SHA-256(h || canonical_CBOR(ServerHello_without_sig))
transcript_hash = h
```

Signatures use domain separator "aafp-v1-handshake" (per H1):
```
ClientHello.signature = ML-DSA-65.Sign(sk, "aafp-v1-handshake" || SHA-256(tls_binding || canonical_CBOR(ClientHello_without_sig_and_mac)))
ServerHello.signature = ML-DSA-65.Sign(sk, "aafp-v1-handshake" || SHA-256(tls_binding || CH_CBOR || SH_CBOR))
ClientFinished.signature = ML-DSA-65.Sign(sk, "aafp-v1-handshake" || h)
```

Session ID derivation (RFC-0003 Section 6.3) uses the transcript
hash:
```
Session ID = HKDF-Expand(HKDF-Extract(salt=client_nonce || server_nonce, IKM=h), info="aafp-session-id-v1", L=32)
```

This is now normative (MUST) per the consistency pass (was
RECOMMENDED in the original RFC).

**Status**: CONSISTENT.

### 4. Error Code Consistency

**Status**: CONSISTENT after Amendments H3, H5, H2.

- 2001 (INVALID_SIGNATURE): Used for ML-DSA-65 signature verification
  failures (per H3).
- 2002 (IDENTITY_EXPIRED): Used for expired `expires_at` (per H4).
- 2007 (INVALID_AGENT_ID): Used for AgentId ≠ SHA-256(pubkey) (per
  H3).
- 2009 (RECEIVER_MAC_INVALID): New code for DoS pre-verification
  failure (per H2).
- 8001 (FRAME_TOO_LARGE): Non-fatal by default (per H5).
- 4003 (RECORD_INVALID): Used for invalid AgentRecord in discovery
  (per H12).
- 4004 (RECORD_EXPIRED): Used for expired AgentRecord in discovery
  (per H12).

No error code is used for two different purposes. No two error codes
are used for the same purpose.

**Status**: CONSISTENT.

### 5. Domain Separator Consistency

**Status**: CONSISTENT after Amendment H1.

Domain separators are defined in RFC-0003 Section 3.5:
- "aafp-v1-handshake": Handshake signatures (RFC-0002 §5.6)
- "aafp-v1-record": AgentRecord signatures (RFC-0003 §3.4)
- "aafp-v1-ucan": UCAN token signatures (RFC-0003 §5.4)

All three are referenced consistently across RFC-0002 and RFC-0003.

**Status**: CONSISTENT.

### 6. Extension Format Consistency

**Status**: CONSISTENT after Amendments C3, H2.

- Handshake extensions: CBOR ExtensionEntry maps in ClientHello/
  ServerHello field 6 (per C3).
- Frame extensions: Binary extension blocks in frame body Extension
  section (per RFC-0002 §6.1, unchanged).
- DoS mitigation extension: Type 0x0001, negotiated via handshake
  extension (per H2).

The two extension mechanisms (handshake-level CBOR and frame-level
binary) are distinct and documented as such in RFC-0002 §6.4.

**Status**: CONSISTENT.

### 7. AgentRecord Field Numbering Consistency

**Status**: CONSISTENT after Amendment H8.

AgentRecord fields:
```
1: record_type
2: agent_id
3: public_key
4: capabilities
5: endpoints
6: created_at
7: expires_at
8: signature
9: key_algorithm (per H8)
```

The signature (field 8) is computed over fields 1-7 and 9 (excluding
field 8). The key_algorithm field is included in the signature to
prevent algorithm substitution.

**Status**: CONSISTENT.

### 8. Conformance Requirements Consistency

**Status**: CONSISTENT after Amendment C6.

RFC-0001 Section 7.3 now references RFC-0006 Section 8.1 as the
normative conformance definition. RFC-0006 Section 8.1 should be
updated to include the new requirements from these amendments:

Add to RFC-0006 Section 8.1:
```
13. Computes the TLS channel binding value and includes it in the
    handshake transcript (per RFC-0002 Section 5.6).
14. Uses domain separators in all signature computations (per
    RFC-0003 Section 3.5).
15. Includes the key_algorithm field in ClientHello, ServerHello,
    and AgentRecord (per RFC-0003 Section 2.3).
16. Includes the expires_at field in ClientHello and ServerHello
    (per RFC-0002 Sections 5.3, 5.4).
17. Uses integer keys for all CBOR structures (per RFC-0002 Section
    8).
```

**Status**: CONSISTENT with this update.

### 9. Cross-Reference Consistency

All cross-RFC references were verified:

- RFC-0001 §7.3 → RFC-0006 §8.1 (conformance) ✓
- RFC-0002 §5.6 → RFC-0003 §6.3 (session ID) ✓
- RFC-0002 §5.6 → RFC 8446 §7.5 (TLS exporter) ✓
- RFC-0002 §6.4 → RFC-0006 §3 (extension registry) ✓
- RFC-0003 §2.1 → RFC-0005 §3.3 (error code 2007) ✓
- RFC-0003 §3.4 → RFC-0002 §8 (canonical CBOR) ✓
- RFC-0003 §3.5 → RFC-0002 §5.6 (domain separator in handshake) ✓
- RFC-0003 §7.3 → RFC-0002 §6.4 (extension negotiation) ✓
- RFC-0004 §3.3 → RFC-0002 §4.3 (RPC format) ✓
- RFC-0005 §4.4 → RFC-0002 §3.4 (FRAME_TOO_LARGE handling) ✓
- RFC-0006 §8.1 → all RFCs (conformance requirements) ✓

**Status**: CONSISTENT.

### 10. Hidden Assumptions Check

The following hidden assumptions were identified and made explicit:

1. **TLS exporter availability**: The protocol assumes the TLS
   implementation supports RFC 8446 exporters. This is now explicit
   in RFC-0002 §5.6 (MUST NOT proceed if exporter unavailable).

2. **Canonical CBOR for signature input**: The protocol assumes
   canonical CBOR encoding for all signature computations. This is
   now explicit in RFC-0002 §5.6 and RFC-0003 §3.4.

3. **Integer key CBOR maps**: The protocol assumes all CBOR maps use
   integer keys. This is now explicit in RFC-0002 §8 and the key
   mapping table.

4. **Domain separation**: The protocol assumes signatures include
   domain separators. This is now explicit in RFC-0003 §3.5.

5. **QUIC stream 0 remains open**: The protocol assumes stream 0
   (handshake stream) remains open after the handshake for PING/
   PONG keepalive. This is now explicit in RFC-0002 §4.7.

6. **AgentId derivation is algorithm-independent**: AgentId =
   SHA-256(public_key) regardless of key_algorithm. This is now
   explicit in RFC-0003 §2.3.

**Status**: No hidden assumptions remain.

---

## Amendment Summary

| ID | Issue | Severity | Wire Change | Backward Compatible | New RFC Sections |
|----|-------|----------|-------------|---------------------|------------------|
| C1 | CBOR key type inconsistency | Critical | Yes | No (v0.1) | RFC-0002 §8 (key table) |
| C2 | Undefined transcript | Critical | Yes | No (v0.1) | RFC-0002 §5.6 |
| C3 | Undefined extension format | Critical | Yes | No (v0.1) | RFC-0002 §6.4 |
| C4 | RPC params encoding | Critical | Yes | No (v0.1) | RFC-0002 §4.3-4.4, RFC-0004 §3.3 |
| C5 | No TLS channel binding | Critical | Yes | No (v0.1) | RFC-0002 §5.6, §2.5 |
| C6 | Stale conformance section | Critical | No | Yes | RFC-0001 §7.3 |
| H1 | No domain separation | High | Yes | No (v0.1) | RFC-0003 §3.5 |
| H2 | No DoS pre-verification | High | Yes (optional) | Yes (optional field) | RFC-0002 §5.8 |
| H3 | Error code 2001 vs 2007 | High | No | Yes | RFC-0003 §2.1 |
| H4 | Missing expires_at | High | Yes | No (v0.1) | RFC-0002 §5.3-5.4 |
| H5 | FRAME_TOO_LARGE contradiction | High | No | Yes | RFC-0005 §4.4 |
| H6 | PING/PONG semantics | High | No | Yes | RFC-0002 §4.7-4.8 |
| H7 | Signature ambiguity | High | — | — | Resolved by C1+C2 |
| H8 | No algorithm agility | High | Yes | No (v0.1) | RFC-0003 §2.3 |
| H9 | Extension negotiation | High | — | — | Resolved by C3 |
| H10 | No revocation | High | No | Yes | RFC-0003 §8.4 |
| H11 | TOFU MITM mitigation | High | No | Yes | RFC-0003 §2.5, §8.3 |
| H12 | Bootstrap amplification | High | No | Yes | RFC-0004 §3.4 |

**Wire protocol changes**: 9 amendments change the wire protocol
(C1, C2, C3, C4, C5, H1, H2, H4, H8). All are justified because no
independent v1 implementations exist. The v0.1 MVP is explicitly
not v1-compatible.

**No backward compatibility concerns**: All wire-protocol-changing
amendments break v0.1 compatibility, which is already declared
incompatible (RFC-0006 §2.1). No independent v1 implementations
exist.

**Cross-RFC consistency**: Verified across 10 dimensions. No
contradictions or hidden assumptions remain after the consistency
pass.

---

## Final Notes on Design Philosophy

The user's guidance about not overcorrecting based on protocol
comparisons was carefully considered:

1. **Domain separation (H1)**: Adopted as a protocol requirement.
   This aligns with established cryptographic practice (libp2p,
   TLS, WireGuard) and is a one-way door that must be correct
   before v1.

2. **Running transcript hash (C2)**: Adopted as a protocol
   requirement. TLS 1.3 and Noise both use this pattern. It is
   more efficient and is the standard approach.

3. **DoS pre-verification (H2)**: Adopted as an OPTIONAL deployment
   profile, NOT a core protocol requirement. This respects the
   user's guidance that "whether it belongs in the core protocol
   versus an optional deployment profile depends on your threat
   model." AAFP serves both Internet-facing and private
   deployments; the optional profile allows each to choose.

4. **Self-describing identifier (multihash)**: NOT adopted for v1.
   The user's guidance that "it also affects identifier size and
   ecosystem compatibility" is correct. The `key_algorithm` field
   (H8) provides algorithm agility for signatures without changing
   AgentId size. AgentId remains 32 bytes (SHA-256). If hash
   function agility is needed in the future, a `hash_algorithm`
   field can be added (similar to `key_algorithm`). Multihash is
   deferred as a future consideration, not a v1 requirement.

5. **Large handshake**: NOT treated as a target for WireGuard-
   sized handshakes. The user's guidance that "AAFP may legitimately
   trade larger handshakes for stronger cryptographic agility,
   richer identity semantics, or capability negotiation" is correct.
   The ~10KB handshake is inherent to ML-DSA-65's key/signature
   sizes. The `key_algorithm` field (H8) allows future use of
   ML-DSA-44 (smaller keys) if deployments choose. Public key
   omission (M2 from REVIEW-0002) is deferred as a future
   optimization, not a v1 requirement.

The amendments follow the principle: adopt established standards
where they reduce maintenance (TLS exporter, CBOR integer keys,
domain separation, running transcript hash), make protocol
requirements normative where interoperability demands it (CBOR
keys, transcript, extensions, channel binding, algorithm field),
and leave implementation choices as recommendations where the
threat model varies (DoS profile, revocation, fingerprint display).
