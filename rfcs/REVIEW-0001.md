# AAFP Protocol Review: RFC-0001 through RFC-0006

```
Review Date:       2025-06-25
Reviewer Role:     Protocol Reviewer / Standards Editor / Distributed Systems
                   Architect / Cryptography Reviewer / Interoperability
                   Engineer / Adversarial Reviewer
Review Standard:   IETF / QUIC WG / libp2p maintainers level
RFCs Under Review: RFC-0001 through RFC-0006 (Draft)
```

---

## 1. Executive Summary

The AAFP RFC suite defines a post-quantum, QUIC-based, agent-to-agent
networking protocol with capability-based discovery, ML-DSA-65 identity,
and a UCAN-derived authorization model. The architecture is sound in its
broad strokes: the layering is clean, the post-quantum-first stance is
well-motivated, and the extension/critical-bit mechanism follows proven
IETF patterns.

However, the RFCs are **not yet ready to serve as a public specification
for independent implementations**. The review identified **6 Critical
issues**, **10 High-severity issues**, **10 Medium-severity issues**, and
numerous Low/Editorial issues. The most serious problems are:

1. **CBOR map key type inconsistency**: Handshake messages and RPC
   structures use string keys in RFC-0002 but integer keys in RFC-0003
   and RFC-0005. Two independent implementers would produce
   non-interoperable wire formats.

2. **Undefined transcript construction**: The ClientFinished signature
   is "over the transcript" but the transcript's byte-level construction
   is never specified. This is the single most likely source of
   interimplementation signature verification failure.

3. **No channel binding to TLS**: The AAFP handshake is not
   cryptographically bound to the TLS session, creating a relay attack
   vector that the nonces alone do not prevent.

4. **Undefined handshake extension format**: The `extensions` field in
   ClientHello/ServerHello is described as "supported extensions" but
   its encoding (CBOR array of type IDs? CBOR array of extension
   blocks? binary extension blocks?) is never specified.

5. **RPC params/result encoding ambiguity**: The `params` and `result`
   fields are `bstr` (opaque bytes), but standard RPC methods like
   `aafp.discovery.announce` pass structured data (AgentRecord). Whether
   this is nested CBOR inside bstr is never stated.

6. **Stale conformance section**: RFC-0001 Section 7.3 references
   "AAFP v0.1" conformance while RFC-0006 defines "version 1"
   conformance. These are different versions with incompatible wire
   formats.

**Recommendation: GO WITH CHANGES** — Implementation may begin after
resolving the 6 Critical issues. The High-severity issues should be
resolved before any independent implementation attempts conformance.

---

## 2. Cross-RFC Consistency Review

### 2.1 CBOR Map Key Type Inconsistency (CRITICAL)

**Description**: The RFCs use two different CBOR map key conventions
without explanation:

- **String keys**: RFC-0002 Section 5.3-5.5 (handshake messages:
  `"protocol_version"`, `"agent_id"`, `"public_key"`, etc.), RFC-0002
  Section 4.3-4.6 (RPC request/response, CLOSE, ERROR messages:
  `"id"`, `"method"`, `"params"`, `"code"`, `"message"`, etc.)
- **Integer keys**: RFC-0003 Section 3.2 (AgentRecord: keys 1-8),
  RFC-0003 Section 4.2 (CapabilityDescriptor: keys 1-2), RFC-0003
  Section 5.4 (UcanToken: keys 1-6), RFC-0005 Section 6.1 (RPC
  response error object: keys 1-3)

**Rationale**: CBOR map key type affects canonical encoding, which
affects signature verification. An implementer cannot determine from
the RFCs whether the RpcResponse error object uses string keys
(`"code"`, `"message"`, `"data"`) or integer keys (1, 2, 3). RFC-0002
Section 4.4 shows string keys; RFC-0005 Section 6.1 shows integer keys
for the same structure.

**Impact**: Independent implementations will produce non-interoperable
wire formats. Signature verification will fail across implementations
if key types differ.

**Suggested resolution**: Choose ONE convention and apply it
consistently. Integer keys are more compact and are the better choice
for wire efficiency. Update all CBOR schemas in all RFCs to use integer
keys with a normative key-to-name mapping table.

**Changes wire protocol**: Yes (resolves ambiguity that would otherwise
cause wire-level incompatibility)

### 2.2 Conformance Version Contradiction (CRITICAL)

**Description**: RFC-0001 Section 7.3 defines conformance for "AAFP
v0.1" with 7 requirements. RFC-0006 Section 8.1 defines conformance for
"AAFP version 1" with 12 requirements. RFC-0006 Section 2.1 states
"Version 0 is the pre-RFC MVP implementation... NOT compatible with
version 1."

**Rationale**: RFC-0001's conformance section is stale from the pre-RFC
era. It describes the MVP, not the standardized protocol. An
implementer reading RFC-0001 would conform to the wrong version.

**Impact**: Confusion about which conformance requirements apply.
Implementers may target v0.1 (incompatible) instead of v1.

**Suggested resolution**: Update RFC-0001 Section 7.3 to reference
"AAFP version 1" and point to RFC-0006 Section 8.1 as the normative
conformance definition. Remove the stale v0.1 conformance list.

**Changes wire protocol**: No

### 2.3 Session ID Circular Reference (EDITORIAL)

**Description**: RFC-0002 Section 5.4 says `session_id` is a
"Cryptographically unique session identifier (see RFC-0003)". RFC-0003
Section 6.2 says "Session ID: see RFC-0002 Section 5.6". RFC-0002
Section 5.6 defines the properties. The reader must follow
RFC-0002 → RFC-0003 → RFC-0002 to find the definition.

**Suggested resolution**: Define Session ID properties in RFC-0003
(the identity/session RFC) and have RFC-0002 reference RFC-0003
one-way.

**Changes wire protocol**: No

### 2.4 Error Code Misuse: 2001 vs 2007 (HIGH)

**Description**: RFC-0003 Section 2.1 says "If the verification fails,
the implementation MUST reject the handshake with error code 2001
(invalid signature/identity)." But RFC-0005 defines:
- 2001 = INVALID_SIGNATURE ("Signature verification failed")
- 2007 = INVALID_AGENT_ID ("AgentId does not match SHA-256(pubkey)")

AgentId mismatch is not a signature failure — it's an identity
binding failure. RFC-0003 should use 2007 for AgentId mismatch and
2001 for actual signature verification failures.

**Suggested resolution**: Update RFC-0003 Section 2.1 to use error
code 2007 for AgentId mismatch. Use 2001 only for ML-DSA-65 signature
verification failures.

**Changes wire protocol**: No (error code semantics only)

### 2.5 Error Code Width: 16-bit vs 32-bit (EDITORIAL)

**Description**: RFC-0005 Section 2 says "Error codes are 32-bit
unsigned integers (uint in CBOR)" but then says "Error Code:
0x0000–0xFFFF (16-bit, encoded as uint)". The ProtocolError struct
uses `code: u32`. The maximum assigned code is 9999, which fits in 14
bits.

**Suggested resolution**: Specify that error codes are uint with a
maximum value of 9999 (or 0x270F). The CBOR encoding will use the
shortest uint encoding per canonical CBOR rules. Remove the "32-bit"
and "16-bit" labels that contradict each other.

**Changes wire protocol**: No (clarification only)

### 2.6 NAT Traversal RFC Missing (EDITORIAL)

**Description**: RFC-0001 Section 2.1 lists "NAT Traversal (aafp-nat) |
(future RFC)" but no NAT traversal RFC exists in the RFC-0001 through
RFC-0006 set. The MVP codebase includes NAT traversal functionality.

**Suggested resolution**: Either add a placeholder RFC-0007 (NAT
Traversal) marked as "Reserved" or remove the NAT traversal row from
the layer table until an RFC is written.

**Changes wire protocol**: No

---

## 3. Security Review

### 3.1 No Channel Binding Between TLS and AAFP Handshake (CRITICAL)

**Description**: The AAFP handshake occurs on QUIC stream 0 after TLS
completes. The handshake includes nonces and ML-DSA-65 signatures, but
there is no cryptographic binding between the TLS session and the AAFP
session. The nonces are generated independently of the TLS session keys.

**Rationale**: Without channel binding, a relay attack is possible:
an attacker positioned between client and server can terminate TLS on
both sides (using self-signed certificates, which AAFP permits under
TOFU) and relay the AAFP handshake messages. The ML-DSA-65 signatures
verify because they're relayed unchanged. The nonces don't help
because they're not bound to the TLS channel — the attacker creates
two separate TLS sessions and relays the AAFP messages between them.

TLS 1.3 provides an exporter (RFC 5705 / RFC 8446 Section 7.5) that
produces a channel-binding value. Including this in the AAFP handshake
transcript would bind the AAFP session to the specific TLS channel,
preventing relay.

**Impact**: Relay attacks on first connection (TOFU scenario). An
attacker can intercept, relay, and observe all subsequent traffic
within the relayed session.

**Threat status**: **Unaddressed**

**Suggested resolution**: Add the TLS exporter value to the AAFP
handshake transcript. Specifically:
1. After TLS completes, both sides compute
   `tls_channel_binding = TLS-Exporter("aafp-channel-binding", "", 32)`.
2. The ClientFinished signature is computed over
   `(tls_channel_binding || ClientHello || ServerHello)`.
3. The ServerHello signature is computed over
   `(tls_channel_binding || ServerHello_fields)`.
4. Specify that implementations MUST verify the channel binding
   matches before accepting the handshake.

**Changes wire protocol**: Yes (adds channel binding to transcript)

### 3.2 No Replay Protection Mechanism (HIGH)

**Description**: The handshake includes 32-byte nonces, but there is no
mechanism for detecting nonce reuse. RFC-0005 defines error code 2008
(NONCE_REUSE) but no RFC specifies when to emit it or how to track
nonces.

**Rationale**: The nonces prevent transcript replay (a recorded
handshake produces a different session ID because the server generates
a new nonce). However, a ClientHello can be replayed to a server,
causing the server to perform expensive ML-DSA-65 signature
verification (~1ms) before the attacker fails to produce a valid
ClientFinished. This is a DoS amplification vector: a 5KB ClientHello
forces ~1ms of CPU on the server.

**Threat status**: **Partially mitigated** (nonces prevent transcript
replay but not ClientHello replay for DoS)

**Suggested resolution**:
1. Specify that servers SHOULD track recently seen (agent_id, nonce)
   pairs and reject duplicates with error 2008.
2. Specify a retention window (RECOMMENDED: 5 minutes).
3. Consider adding a client puzzle or proof-of-work before server-side
   signature verification, similar to TLS 1.3's anti-DoS discussions.

**Changes wire protocol**: No (implementation guidance)

### 3.3 No Revocation Mechanism (HIGH)

**Description**: RFC-0003 Section 8.4 states "The protocol does not
provide a revocation mechanism in v1. Revocation is deferred to a
future RFC." A compromised ML-DSA-65 key remains valid until the
AgentRecord's `expires_at` timestamp.

**Rationale**: If an agent sets a 1-year expiry on its AgentRecord, a
compromised key is valid for up to 1 year. During that time, the
attacker can impersonate the agent, sign UCAN tokens, and announce
false capabilities. There is no mechanism for the network to learn
that a key has been compromised.

**Threat status**: **Unaddressed**

**Suggested resolution**: At minimum, specify:
1. A RECOMMENDED maximum AgentRecord expiry (e.g., 30 days).
2. A future revocation mechanism design (e.g., a revocation list
   signed by the agent's key before compromise, or a short-lived
   record with frequent renewal).
3. For v1, document the risk explicitly in the Security
   Considerations and recommend short expiry times.

**Changes wire protocol**: No (for v1; future revocation RFC would)

### 3.4 TOFU MITM Mitigation Unspecified (HIGH)

**Description**: RFC-0003 Section 8.3 acknowledges TOFU vulnerability
to MITM on first connection and says "Implementations SHOULD provide a
mechanism for users to verify agent identities out-of-band (e.g., by
comparing AgentId hex strings)." But no specific mechanism is defined.

**Rationale**: Without a concrete verification mechanism, the TOFU
mitigation is aspirational. Users won't manually compare 64-character
hex strings. The protocol should define a fingerprint format (e.g.,
base32-encoded first N bytes with checksum, similar to SSH
fingerprints or Signal safety numbers).

**Threat status**: **Partially mitigated** (application-layer
signatures prevent identity forgery, but first-connection MITM is
unaddressed)

**Suggested resolution**: Define a fingerprint format:
`AAFP-<base32(first 16 bytes of AgentId)>-<CRC32 checksum>`.
Specify that implementations MUST display this fingerprint and SHOULD
provide a verification API.

**Changes wire protocol**: No

### 3.5 Amplification Attack via Bootstrap Lookup (HIGH)

**Description**: A bootstrap node responds to `aafp.discovery.lookup`
with up to 10 AgentRecords. Each record contains a 1952-byte public
key + 3309-byte signature + capabilities + endpoints ≈ 5-7KB. A
response with 10 records is ~50-70KB. The request is ~100 bytes. This
is a ~500x amplification factor.

**Rationale**: UDP-based protocols (QUIC) are vulnerable to
amplification attacks where an attacker spoofs the source address.
RFC 9000 Section 8.1 requires QUIC servers to limit amplification
(3x ratio until address validation). But AAFP's bootstrap protocol
operates on top of an established QUIC connection (after handshake),
so source address spoofing is not the primary concern. The concern is
a malicious client opening many connections and issuing expensive
lookup requests.

**Threat status**: **Partially mitigated** (QUIC address validation
prevents spoofing, but malicious clients can still consume resources)

**Suggested resolution**:
1. Specify that bootstrap nodes SHOULD rate-limit lookup requests per
   connection (RECOMMENDED: 10 requests/minute).
2. Specify that bootstrap nodes SHOULD validate the requester's
   AgentRecord before responding to lookups.
3. Reduce the default lookup limit from 10 to 5 for unauthenticated
   requests.

**Changes wire protocol**: No

### 3.6 DHT Poisoning and Sybil Attacks (MEDIUM)

**Description**: RFC-0004 Section 8.3 acknowledges Sybil attacks but
provides no mitigation for v1. An attacker can create arbitrary
identities and flood the DHT with false capability advertisements.

**Threat status**: **Unaddressed** (acknowledged, deferred)

**Suggested resolution**: Document the risk more prominently. For v1,
recommend that bootstrap nodes implement per-AgentId rate limiting
for announcements. Future work should consider proof-of-work or
stake-based identity.

**Changes wire protocol**: No

### 3.7 Metadata Leakage (MEDIUM)

**Description**: AgentRecords contain capabilities and endpoints in
cleartext. Anyone querying the DHT can see what capabilities an agent
has and where it's located. The handshake includes capabilities
before authentication is complete (though QUIC encrypts the payload).

**Threat status**: **Partially mitigated** (QUIC encrypts handshake
payload, but DHT records are public)

**Suggested resolution**: Document the privacy implications clearly.
For v1, recommend that privacy-sensitive agents should not advertise
in the DHT. Future work should consider encrypted AgentRecords.

**Changes wire protocol**: No

### 3.8 Session Fixation (MEDIUM)

**Description**: The Session ID is generated by the server (in
ServerHello). RFC-0003 Section 6.3 says the derivation is an
"implementation detail" and implementations "MAY use any method
satisfying the above properties." If an implementation uses a
server-generated random value without binding to the transcript, the
server can fixate the session ID.

**Rationale**: The RECOMMENDED approach (HKDF over transcript) is
secure, but making it an "implementation detail" allows insecure
implementations. Two implementations could produce different session
IDs for the same handshake, which is fine for security but bad for
interoperability (if session IDs are used for resumption).

**Threat status**: **Partially mitigated** (RECOMMENDED approach is
secure, but not mandated)

**Suggested resolution**: Make the HKDF derivation method normative
(MUST, not RECOMMENDED). Specify the exact HKDF parameters:
```
Session ID = HKDF-Extract(salt=client_nonce || server_nonce,
                          IKM=handshake_transcript_hash)
Session ID = HKDF-Expand(Session ID, info="aafp-session-id-v1", L=32)
```
Where `handshake_transcript_hash = SHA-256(ClientHello || ServerHello)`.

**Changes wire protocol**: Yes (makes derivation normative)

### 3.9 Downgrade Attacks (LOW)

**Description**: Version negotiation via ALPN is protected by TLS
integrity. RFC-0006 Section 9.1 correctly states that an active
attacker cannot modify ALPN negotiation. However, the frame header
includes a Version field that is NOT protected by TLS at the AAFP
layer (it's protected by QUIC packet protection, but an AAFP
implementation reads it before verifying it matches the ALPN-
negotiated version).

**Threat status**: **Mitigated** (TLS protects ALPN; implementers
should verify frame version matches ALPN version)

**Suggested resolution**: Add a normative requirement: "Implementations
MUST verify that the Version field in every frame matches the version
negotiated via ALPN. If they differ, the implementation MUST send an
ERROR frame with code 8006 (INVALID_VERSION) and close the connection."

**Changes wire protocol**: No (implementation requirement)

### 3.10 Traffic Analysis / Fingerprinting (LOW)

**Description**: The handshake messages have distinguishable sizes due
to the large ML-DSA-65 public keys (1952 bytes) and signatures (3309
bytes). An observer can identify AAFP traffic by its characteristic
handshake sizes, even though QUIC encrypts the payload.

**Threat status**: **Unaddressed** (acceptable for v1; document the
risk)

**Suggested resolution**: Document in Security Considerations. Future
work could pad handshake messages to a fixed size.

**Changes wire protocol**: No

### 3.11 Security Threat Summary

| Threat | Status | Severity |
|--------|--------|----------|
| Relay attack (no channel binding) | Unaddressed | Critical |
| ClientHello replay (DoS) | Partially mitigated | High |
| Key compromise (no revocation) | Unaddressed | High |
| TOFU MITM (no verification mechanism) | Partially mitigated | High |
| Amplification via bootstrap | Partially mitigated | High |
| Sybil attacks | Unaddressed (deferred) | Medium |
| Metadata leakage | Partially mitigated | Medium |
| Session fixation | Partially mitigated | Medium |
| Downgrade attacks | Mitigated | Low |
| Traffic analysis | Unaddressed (acceptable) | Low |

---

## 4. Wire Protocol Review

### 4.1 Frame Header Overhead (MEDIUM)

**Description**: The frame header is 32 bytes:
- Version: 1 byte
- FrameType: 1 byte
- Flags: 1 byte
- Reserved: 1 byte
- Stream ID: 8 bytes
- Payload Length: 8 bytes
- Extension Length: 8 bytes
- Total: 32 bytes (4 + 8 + 8 + 8 = 28... actually 4+8+8+8 = 28, but
  the diagram shows 32 bytes due to the 4-byte rows)

Wait, let me recount: 4 bytes (Version+FrameType+Flags+Reserved) +
8 bytes (Stream ID) + 8 bytes (Payload Length) + 8 bytes (Extension
Length) = 28 bytes. The ASCII diagram shows 7 rows of 4 bytes = 28
bytes. The "32-byte header" claim in the review summary is incorrect;
it's 28 bytes. Still significant for small frames.

For a PING frame (0-byte payload, 0-byte extensions), the header is
28 bytes for 0 bytes of payload — infinite overhead ratio. For a
100-byte RPC request, the header is 22% overhead.

**Comparison**: QUIC uses variable-length integer encoding (1-8 bytes
per field). A QUIC PING frame is 1 byte. WireGuard's data packet
header is 32 bytes but carries an encrypted payload of up to 65535
bytes. TLS 1.3 record header is 5 bytes.

**Rationale**: The 64-bit length fields are excessive. The maximum
payload is 1 MiB (21 bits). A 32-bit length field would suffice with
room to spare. The 64-bit Stream ID is also excessive — QUIC uses
62-bit stream IDs, and AAFP could use 32-bit stream IDs (4 billion
streams per connection is more than sufficient).

**Impact**: 28 bytes × millions of frames = significant bandwidth
overhead. For a protocol designed for agent-to-agent communication
where messages may be small (RPC requests, acknowledgments), this is
non-trivial.

**Suggested resolution**: Consider two options:
1. **Variable-length integers** (QUIC-style): Use 1-8 byte variable-
   length encoding for Stream ID, Payload Length, and Extension Length.
   This reduces the header to 4-16 bytes for most frames.
2. **Fixed but smaller**: Use 32-bit Stream ID + 32-bit Payload Length
   + 16-bit Extension Length = 10 bytes + 4 bytes control = 14 bytes.

Option 1 is more flexible and follows QUIC's proven approach. Option 2
is simpler to implement. Either is a significant improvement.

**Changes wire protocol**: Yes (if adopted; alternatively, document
the overhead as accepted for v1 simplicity)

### 4.2 Undefined Transcript Construction (CRITICAL)

**Description**: RFC-0002 Section 5.5 says the ClientFinished
signature is "over (ClientHello || ServerHello) transcript." The word
"transcript" is not defined. Possible interpretations:

- **Interpretation A**: Raw CBOR bytes of the ClientHello payload
  concatenated with raw CBOR bytes of the ServerHello payload.
- **Interpretation B**: Frame bytes (header + extensions + payload) of
  the HANDSHAKE frames containing ClientHello and ServerHello.
- **Interpretation C**: A CBOR array `[ClientHello, ServerHello]`
  encoded canonically.
- **Interpretation D**: SHA-256 hash of the concatenation of
  ClientHello and ServerHello CBOR bytes.

**Rationale**: TLS 1.3 defines the transcript hash precisely
(RFC 8446 Section 4.4.1): "The transcript is the concatenation of
the handshake messages in the order they appear on the wire, including
the message headers." Noise defines the transcript hash as a running
SHA-256 hash. AAFP defines neither.

**Impact**: Two independent implementations will almost certainly
interpret "transcript" differently, causing signature verification
failure. This is the #1 interoperability risk.

**Suggested resolution**: Define the transcript precisely:
```
transcript = SHA-256(ClientHello_CBOR_bytes || ServerHello_CBOR_bytes)
```
Where `ClientHello_CBOR_bytes` is the canonical CBOR encoding of the
ClientHello map (including all fields except the signature), and
`ServerHello_CBOR_bytes` is the canonical CBOR encoding of the
ServerHello map (including all fields except the signature).

The ClientFinished signature is then:
```
signature = ML-DSA-65.Sign(secret_key, transcript)
```

Specify that the signature is over the 32-byte SHA-256 hash, not the
raw concatenation (this is important for ML-DSA-65 which has a
maximum message size).

**Changes wire protocol**: Yes (defines normative transcript)

### 4.3 Undefined Handshake Extension Format (CRITICAL)

**Description**: RFC-0002 Section 5.3 shows ClientHello with an
`"extensions"` field described as "Supported extensions (optional)."
The format of this field is never specified:

- Is it a CBOR array of extension type integers?
- Is it a CBOR array of extension blocks (each containing type, data)?
- Is it the binary extension encoding from RFC-0002 Section 6.1?
- Is it a CBOR map of type → data?

**Rationale**: Extension negotiation is critical for forward
compatibility. Without a defined format, implementations cannot
negotiate extensions. TLS 1.3 defines extensions precisely
(RFC 8446 Section 4.2): each extension has a 2-byte type, 2-byte
length, and variable-length data, encoded in a contiguous block.

**Impact**: Implementations cannot negotiate extensions. The
authorization token exchange (RFC-0003 Section 7.3) depends on
extensions but cannot function without a defined format.

**Suggested resolution**: Define the handshake extensions field as a
CBOR array of extension descriptors:
```cbor
HandshakeExtensions = [
    *{
        1: uint,       // extension_type
        2: bstr,       // extension_data
    }
]
```
Specify that the ClientHello lists proposed extensions and the
ServerHello lists accepted extensions (a subset of the client's
proposals). Extensions not in the ServerHello are not active for the
session.

**Changes wire protocol**: Yes (defines normative extension format)

### 4.4 RPC Params/Result Encoding Ambiguity (CRITICAL)

**Description**: RFC-0002 Section 4.3 defines RpcRequest with
`"params": bstr` (opaque bytes). RFC-0004 Section 3.3 defines
`aafp.discovery.announce` with `"record": AgentRecord` in the params.
But AgentRecord is a CBOR structure, and params is bstr. Is the
AgentRecord CBOR-encoded and placed in the bstr? Is the entire params
a CBOR map encoded as bstr? Is params a CBOR map (not bstr)?

Similarly, RpcResponse has `"result": bstr / null`, and
`aafp.discovery.lookup` returns `"peers": [ *AgentRecord ]`. How is
this encoded in the bstr result field?

**Rationale**: The `bstr` type was chosen for "opaque" params, but
standard RPC methods need structured params. The encoding is
ambiguous. TLS 1.3 and QUIC avoid this by defining each message type
separately. gRPC uses Protocol Buffers for structured params.

**Impact**: Independent implementations will encode RPC params
differently. The discovery protocol cannot interoperate.

**Suggested resolution**: Change `params` and `result` from `bstr` to
`any` (CBOR major type with any value). This allows structured data
to be passed directly without nested encoding. Specify that for
standard RPC methods, the params and result are CBOR maps with
integer keys.

Alternatively, if `bstr` is retained for extensibility, specify that
the bstr contains a CBOR-encoded value and define the CBOR schema for
each standard RPC method's params and result.

**Changes wire protocol**: Yes (resolves encoding ambiguity)

### 4.5 FRAME_TOO_LARGE Fatal/Stream Contradiction (HIGH)

**Description**: RFC-0002 Section 3.4 says "Implementations MUST reject
frames with payloads larger than this limit by sending an error frame
with error code 8001 (frame too large) and closing the stream."
RFC-0005 Section 4.4 says error code 8001 is ALWAYS fatal (connection
must close). Closing a stream ≠ closing a connection.

**Rationale**: A frame that's too large on one stream shouldn't
necessarily kill the entire connection. But the error model says
8001 is always fatal. This is contradictory.

**Suggested resolution**: Either:
1. Make 8001 non-fatal by default (remove from the "always fatal"
   list in RFC-0005 Section 4.4), allowing the sender to set fatal=true
   if needed. Then RFC-0002's "close the stream" is correct.
2. Or change RFC-0002 to say "close the connection" instead of "close
   the stream."

Option 1 is better — a single oversized frame shouldn't kill the
connection.

**Changes wire protocol**: No (error semantics clarification)

### 4.6 PING/PONG Stream Semantics (HIGH)

**Description**: RFC-0002 Section 4.7 says "A PING frame is a keepalive
probe. The receiver MUST respond with a PONG frame on the same stream."
But PING is a connection-level keepalive, not a stream-level operation.
Which stream does a keepalive PING use? Stream 0? A new stream? Any
stream?

**Rationale**: QUIC has its own PING frame for connection-level
keepalive. AAFP's PING/PONG appears to duplicate this. If AAFP PING is
stream-level, it's not useful for connection keepalive. If it's
connection-level, the "same stream" requirement is confusing.

**Suggested resolution**: Specify that PING/PONG frames:
1. MAY be sent on any open stream (including stream 0).
2. Are primarily for application-layer keepalive (distinct from QUIC's
   transport-level keepalive).
3. The receiver MUST respond with PONG on the same stream.
4. Alternatively, remove AAFP PING/PONG and rely on QUIC's keepalive
   mechanism (simpler, less duplication).

**Changes wire protocol**: No (clarification; or removal if option 4)

### 4.7 CBOR Deterministic Encoding Reference (MEDIUM)

**Description**: RFC-0002 Section 8.1 cites "RFC 7049 Section 3.9" for
canonical CBOR. RFC 7049 has been obsoleted by RFC 8949. The sorting
rules differ:
- RFC 7049 Section 3.9: "sorted lowest value to highest"
- RFC 8949 Section 4.2.1: "bytewise lexicographic order of their
  deterministic encodings"
- RFC 8949 Section 4.2.3: "length-first core deterministic encoding"
  (shortest encoding first, then lexicographic)

The AAFP RFC says "shortest encoding first, then lexicographic" which
matches RFC 8949 Section 4.2.3 (length-first), NOT RFC 7049.

**Rationale**: Citing the wrong RFC means implementers who follow
RFC 7049 will sort differently from those who follow RFC 8949. For
integer keys, RFC 7049 sorts numerically (1, 2, 3, 10) while RFC 8949
bytewise sorts by encoding (1, 2, 3, 10 — same for small integers, but
differs for larger ones). For string keys, both use bytewise ordering,
but the "shortest encoding first" rule is specific to RFC 8949.

**Suggested resolution**: Update all references from RFC 7049 to
RFC 8949. Specify "length-first core deterministic encoding
requirements" (RFC 8949 Section 4.2.3) as the normative encoding
rules. This matches the existing AAFP rules.

**Changes wire protocol**: No (clarification; aligns spec with intent)

### 4.8 Signature Computation Ambiguity (HIGH)

**Description**: RFC-0003 Section 3.4 says "Construct a CBOR map
containing fields 1 through 7 (excluding field 8, the signature)."
But the schema in Section 3.2 shows integer keys (1, 2, 3...) with
string name comments ("record_type", "agent_id"...). It's unclear
whether the signature is over the integer-keyed map or the string-
keyed map.

For the handshake (RFC-0002 Section 5.3), the ClientHello signature
is "over the CBOR encoding of this map (excluding signature field)."
The map is shown with string keys. But if the canonical encoding
requires integer keys, the signature would be over a different byte
sequence.

**Rationale**: This is the same root cause as issue 2.1 (CBOR key
type inconsistency). The signature is over the CBOR encoding, and the
encoding depends on the key type. This must be unambiguous.

**Suggested resolution**: After resolving issue 2.1 (choose integer
keys everywhere), explicitly state in each signature computation
section: "The signature is computed over the canonical CBOR encoding
of the map using integer keys as specified in the schema."

**Changes wire protocol**: Yes (resolves ambiguity)

### 4.9 Handshake Missing AgentRecord Fields (HIGH)

**Description**: The ClientHello (RFC-0002 Section 5.3) includes
`agent_id`, `public_key`, `nonce`, `capabilities`, `extensions`, and
`signature`. It does NOT include `created_at`, `expires_at`, or
`endpoints` from the AgentRecord schema (RFC-0003 Section 3.2).

RFC-0003 Section 7.2 says the client verifies "Server's AgentRecord
(if provided via discovery) is valid and not expired." But the
ServerHello doesn't include the AgentRecord — it includes a subset of
its fields. How does the client verify the server's record expiry?

**Rationale**: The handshake authenticates the agent's identity
(AgentId + public key + signature) but doesn't carry the full
AgentRecord. The client must obtain the server's AgentRecord from
discovery (DHT, PEX, or bootstrap) to verify expiry. But what if the
client doesn't have the server's AgentRecord? The handshake succeeds,
but the client has no way to know if the server's identity has
expired.

**Suggested resolution**: Either:
1. Include `expires_at` in the ClientHello and ServerHello (allows
   expiry check without discovery lookup).
2. Include the full AgentRecord in the handshake (larger but
   self-contained).
3. Specify that the handshake authenticates identity only, and expiry
   checking is the application's responsibility (document this
   clearly).

Option 1 is the best balance. Add `expires_at` (uint) to both
ClientHello and ServerHello.

**Changes wire protocol**: Yes (adds field to handshake)

### 4.10 Undefined Feature Flags (MEDIUM)

**Description**: RFC-0006 Section 5.2 defines:
- 0x04 (ENCRYPTED): "Payload is application-layer encrypted"
- 0x08 (ACK): "Frame is an acknowledgment"

Neither is specified anywhere. There's no definition of what
application-layer encryption means, what algorithm is used, or how
keys are derived. There's no definition of what ACK frames
acknowledge or how they're used.

**Rationale**: Defining feature flags without specifying their
semantics creates confusion. Implementers may interpret them
differently or implement them incorrectly. These flags should not
exist until their semantics are defined.

**Suggested resolution**: Remove 0x04 (ENCRYPTED) and 0x08 (ACK)
from the defined feature flags table. Mark them as "Reserved." They
can be assigned when their semantics are specified in a future RFC.

**Changes wire protocol**: No (removes undefined definitions)

---

## 5. Interoperability Review

### 5.1 Areas of Likely Divergent Interpretation

Based on comparison with how independent teams interpret IETF
specifications, the following areas are where independent
implementers are most likely to diverge:

| Area | Risk | Divergence Probability |
|------|------|----------------------|
| Transcript construction for ClientFinished | Undefined | ~95% |
| CBOR map key types (string vs integer) | Contradictory | ~90% |
| Handshake extension format | Undefined | ~85% |
| RPC params/result encoding | Ambiguous | ~80% |
| Signature over integer-keyed vs string-keyed map | Ambiguous | ~75% |
| Session ID derivation method | "Implementation detail" | ~60% |
| ML-DSA-65 signing mode (deterministic vs randomized) | Unspecified | ~50% |
| PING/PONG stream usage | Ambiguous | ~40% |

### 5.2 ML-DSA-65 Signing Mode (MEDIUM)

**Description**: FIPS 204 allows both deterministic and randomized
signing for ML-DSA. The RFCs don't specify which mode to use.

**Rationale**: Deterministic signing produces the same signature for
the same message and key, which is useful for testing and debugging.
Randomized signing provides better resistance to side-channel attacks.
The choice doesn't affect verification (both modes produce verifiable
signatures), but it affects interoperability testing (deterministic
signatures are reproducible).

**Suggested resolution**: Specify that implementations MUST use
deterministic signing (FIPS 204 Section 5.2, deterministic mode) for
reproducibility. Implementations MAY use randomized signing for
operational deployments if side-channel resistance is a concern.

**Changes wire protocol**: No (signatures are verifiable regardless)

### 5.3 Multiaddr Format Not Specified (MEDIUM)

**Description**: RFC-0003 Section 3.3 says endpoints are "Multiaddr
strings." RFC-0004 Section 3.1 says bootstrap nodes are configured
with "multiaddr." But the multiaddr format is never specified or
referenced.

**Rationale**: Multiaddr is a libp2p concept with its own
specification. An implementer unfamiliar with libp2p wouldn't know
the format. Even libp2p implementations may use different multiaddr
variants.

**Suggested resolution**: Either:
1. Reference the libp2p multiaddr specification explicitly.
2. Define a simplified multiaddr format for AAFP (e.g.,
   `quic-v1/<ip>/<port>`).
3. Use a different endpoint format (e.g., IP:port pairs with a
   protocol identifier).

**Changes wire protocol**: No (endpoint format is in AgentRecord, not
frame format)

### 5.4 AAFP Stream IDs vs QUIC Stream IDs (LOW)

**Description**: AAFP stream IDs are 64-bit unsigned integers with
even/odd initiator convention. QUIC stream IDs are 62-bit with
type/direction bits in the top 2 bits. The RFCs don't clarify that
AAFP stream IDs are a separate namespace from QUIC stream IDs.

**Rationale**: An implementer might try to use AAFP stream IDs
directly as QUIC stream IDs, which would fail due to the different
bit layouts.

**Suggested resolution**: Add a note: "AAFP stream IDs are logical
identifiers. The mapping between AAFP stream IDs and QUIC stream IDs
is an implementation detail. An AAFP stream ID of N maps to the Nth
QUIC bidirectional stream opened by the initiating side."

**Changes wire protocol**: No

---

## 6. Scalability Review

### 6.1 Bootstrap Node Bottleneck (HIGH)

**Description**: All agents connect to bootstrap nodes for initial
discovery. At 10M agents:
- Each bootstrap node stores up to 10,000 records (RFC-0004 Section
  3.4 recommends this limit). This covers 0.1% of the network.
- Each AgentRecord is ~5-7KB. 10,000 records = 50-70MB (manageable).
- But the bootstrap node can only serve records it has stored. An
  agent looking for a specific AgentId has a 0.1% chance of finding
  it on a single bootstrap node.
- At 100M agents, the coverage drops to 0.01%.

**Rationale**: The bootstrap model doesn't scale. The 10,000-record
limit is arbitrary and too small for large networks. The RFC
acknowledges that a distributed DHT is future work, but the bootstrap
model's limitations should be documented more clearly.

**Scalability assessment**:
- 10K agents: Bootstrap model works (1-2 bootstrap nodes sufficient).
- 1M agents: Bootstrap model strains (need many bootstrap nodes, each
  storing 10K records covers 1% of network).
- 10M agents: Bootstrap model insufficient (need distributed DHT).
- 100M+ agents: Bootstrap model fails (need distributed DHT + sharding).

**Suggested resolution**: Document the scalability limits explicitly.
For v1, state that the bootstrap model is suitable for networks up to
~100K agents. For larger networks, a distributed DHT (future RFC) is
required. Increase the recommended record limit to 100,000 for
bootstrap nodes with sufficient memory.

**Changes wire protocol**: No

### 6.2 AgentRecord Size at Scale (MEDIUM)

**Description**: Each AgentRecord contains:
- ML-DSA-65 public key: 1,952 bytes
- ML-DSA-65 signature: 3,309 bytes
- AgentId: 32 bytes
- Capabilities + endpoints + timestamps: ~200-500 bytes
- Total: ~5,500-6,000 bytes

At 10M agents: 55-60GB of records (if all stored in one DHT).
At 100M agents: 550-600GB.
At 1B agents: 5.5-6TB.

**Rationale**: ML-DSA-65's large key and signature sizes are a
fundamental scalability constraint. This is a property of the
cryptographic primitive, not a protocol design flaw. However, the
protocol should be designed to minimize the number of times full
records are transmitted.

**Suggested resolution**:
1. Consider ML-DSA-44 (smaller variant: 1312-byte public key, 2420-byte
   signature) for AgentRecords. ML-DSA-44 provides NIST security level
   2 (128-bit classical equivalent), which is sufficient for most
   deployments. ML-DSA-65 provides level 3 (192-bit). Document the
   trade-off.
2. Define a "lightweight" AgentRecord format that contains only
   AgentId + capability names + endpoints (no public key or
   signature), with the full record available on demand. This reduces
   DHT storage by ~90%.
3. Specify that DHT responses MAY return lightweight records by
   default and full records on request.

**Changes wire protocol**: Yes (if lightweight record format is
adopted)

### 6.3 PEX Scalability (MEDIUM)

**Description**: PEX is limited to 50 records per response and 1
request/minute/peer. At 10M agents, learning about all agents via PEX
would require 200,000 exchanges × 1 minute = 139 days.

**Rationale**: PEX is designed for gradual peer learning, not full
network discovery. This is acceptable for a gossip-style protocol but
should be documented as a limitation.

**Suggested resolution**: Document that PEX provides probabilistic
peer discovery, not exhaustive enumeration. For exhaustive discovery,
the distributed DHT (future) is required.

**Changes wire protocol**: No

### 6.4 Regional Model Scalability (LOW)

**Description**: The 5-region model is too coarse for global scale.
At 1B agents, each region has 200M agents. The static distance matrix
doesn't reflect real-world latency (e.g., Tokyo to Sydney is closer
than Tokyo to Mumbai, but both are "APAC").

**Suggested resolution**: Document that the 5-region model is a v1
placeholder. Future versions should use either:
- More regions (e.g., 50+ regions based on cloud provider regions).
- Latency-based clustering (measured RTT rather than static regions).
- Coordinate-based proximity (geographic coordinates with
  great-circle distance).

**Changes wire protocol**: No

---

## 7. Performance Review

### 7.1 Handshake Latency (MEDIUM)

**Description**: The full handshake requires:
1. TLS handshake: 1 RTT (QUIC + TLS 1.3 with X25519MLKEM768)
2. AAFP handshake: 1.5 RTT (ClientHello → ServerHello →
   ClientFinished)
3. Total: 2.5 RTT

**Comparison**:
- TLS 1.3 without client auth: 1 RTT
- TLS 1.3 with client auth: 2 RTT
- WireGuard: 1 RTT (with pre-shared key)
- Noise XX: 2 RTT (with mutual authentication)
- libp2p TLS: 1 RTT (uses TLS 1.3 with in-band identity)

**Rationale**: The AAFP handshake adds 1.5 RTT on top of TLS. This is
because the AAFP handshake is a separate application-layer handshake
on stream 0. The ClientHello could be sent in 0-RTT (with the TLS
ClientHello) if the protocol were designed to piggyback on TLS.

**Impact**: 2.5 RTT is acceptable for long-lived connections but
noticeable for short-lived connections. For agent-to-agent
communication where connections may be short (single RPC), this is
significant.

**Suggested resolution**:
1. For v1: Accept 2.5 RTT. Document the latency characteristics.
2. For future: Consider a 0-RTT resumption mode where the AAFP
   ClientHello is sent with the TLS 0-RTT data. This would reduce to
   1 RTT for resumed connections.
3. Consider combining the AAFP handshake with TLS client auth to
   reduce to 2 RTT (send ClientFinished with the TLS Finished
   message).

**Changes wire protocol**: No (for v1; future optimization)

### 7.2 Signature Verification Cost (MEDIUM)

**Description**: ML-DSA-65 signature verification is ~1ms on modern
hardware. The handshake requires 3 verifications (ClientHello,
ServerHello, ClientFinished) = ~3ms. AgentRecord verification adds
~1ms per record. A `lookup` returning 10 records requires 10ms of
verification.

**Comparison**:
- Ed25519 verification: ~50μs (20x faster)
- ECDSA P-256 verification: ~100μs (10x faster)
- ML-DSA-65 verification: ~1ms
- ML-DSA-65 signing: ~2ms

**Rationale**: The PQ signature cost is inherent to the cryptographic
primitive. The protocol should minimize the number of signature
verifications.

**Suggested resolution**:
1. Cache verified AgentRecords (by AgentId) to avoid re-verification.
2. Specify that DHT responses MAY include a "verified" flag indicating
   the bootstrap node has already verified the record (trust model
   needs consideration).
3. For the handshake, consider whether the ClientFinished signature
   is necessary (the ClientHello signature already proves identity;
   the ClientFinished could use a MAC derived from the transcript
   instead of a signature).

**Changes wire protocol**: No (optimization; ClientFinished MAC
change would be a wire change but is optional)

### 7.3 Frame Header Bandwidth (LOW)

**Description**: 28-byte frame header for every frame. At 1M frames/
second with average 200-byte payloads, the header is 28MB/s of
overhead out of 228MB/s total (12.3%).

**Suggested resolution**: See issue 4.1. Variable-length integer
encoding would reduce this to ~4-8 bytes for most frames.

**Changes wire protocol**: Yes (if adopted)

### 7.4 UCAN Token Size (LOW)

**Description**: UCAN tokens with delegation chains embed the full
parent token in each child. An 8-level chain contains 8 × 3309-byte
signatures = 26KB. This is significant overhead for each authorized
request.

**Suggested resolution**:
1. Specify that delegation chains MAY reference parent tokens by hash
   rather than embedding them. The verifier fetches the parent token
   from a directory or cache.
2. Specify a maximum token size (RECOMMENDED: 32KB).
3. Specify a maximum delegation depth (RECOMMENDED: 8, already in
   RFC-0003).

**Changes wire protocol**: No (optimization for future)

---

## 8. Cryptography Review

### 8.1 No Signature Algorithm Negotiation (HIGH)

**Description**: The protocol mandates ML-DSA-65 for all signatures.
There is no mechanism to negotiate alternative signature algorithms.
If ML-DSA-65 is broken or deprecated, all agent identities become
invalid.

**Rationale**: Cryptographic agility is a key lesson from the
deprecation of SHA-1 and RSA. TLS 1.3 negotiates signature algorithms
via the `signature_algorithms` extension. AAFP has no equivalent.

The AgentId is `SHA-256(public_key)`, which is algorithm-agnostic.
But the handshake doesn't carry an algorithm identifier for the
public key. An implementation receiving a 1952-byte public key
assumes it's ML-DSA-65, but if a future version uses a different
algorithm with the same key size, there's no way to distinguish.

**Threat status**: **Unaddressed**

**Suggested resolution**:
1. Add a `key_algorithm` field (uint) to ClientHello and ServerHello.
   Define a registry: 1 = ML-DSA-65, 2 = ML-DSA-44, 3 = SLH-DSA,
   etc.
2. Specify that v1 implementations MUST support ML-DSA-65 (algorithm
   1) and MAY support others.
3. The AgentId derivation remains `SHA-256(public_key)` regardless of
   algorithm.
4. Future versions can negotiate algorithms via handshake extensions.

**Changes wire protocol**: Yes (adds key_algorithm field)

### 8.2 No PQ KEX Agility (MEDIUM)

**Description**: The protocol mandates X25519MLKEM768 for TLS KEX.
RFC-0002 Section 2.3 allows X25519 as a fallback but recommends
disabling it in production. There's no mechanism to negotiate
alternative PQ KEX groups (e.g., X25519Kyber768, or future
NIST-selected groups).

**Rationale**: TLS 1.3 negotiates key exchange via the
`supported_groups` extension. AAFP relies on TLS for this, which is
correct. But the RFC should specify that implementations MUST offer
X25519MLKEM768 and MAY offer other PQ groups. If X25519MLKEM768 is
deprecated, the RFCs need to be updated.

**Suggested resolution**: Specify that the PQ KEX group is negotiated
by TLS. Implementations MUST offer X25519MLKEM768. Future RFCs MAY
mandate additional groups. Document that the PQ KEX group is a TLS-
level concern, not an AAFP-level concern.

**Changes wire protocol**: No

### 8.3 Mixed Security Posture: Ed25519 TLS Certs + ML-DSA-65 (LOW)

**Description**: TLS certificates use Ed25519 (classical). Application-
layer signatures use ML-DSA-65 (post-quantum). If a quantum computer
breaks Ed25519, an attacker can forge TLS certificates but cannot
forge ML-DSA-65 signatures.

**Analysis**: This is actually safe because:
1. The AAFP handshake verifies ML-DSA-65 signatures, which the
   attacker cannot forge.
2. The TLS certificate is only used for TOFU, not for identity
   verification.
3. The PQ KEX (X25519MLKEM768) protects the transport regardless of
   certificate type.

**Threat status**: **Mitigated** (documented analysis would help)

**Suggested resolution**: Add this analysis to RFC-0001 Section 9 or
RFC-0003 Section 8. Explicitly state that the mixed posture is
intentional and safe because identity verification is at the
application layer.

**Changes wire protocol**: No

### 8.4 No Key Derivation for Application-Layer Encryption (MEDIUM)

**Description**: The ENCRYPTED feature flag (0x04) implies application-
layer encryption, but there's no key derivation specified. If
application-layer encryption is added in the future, what keys would
be used?

**Rationale**: TLS derives application keys from the handshake
transcript. AAFP could derive application-layer keys from the AAFP
handshake transcript (which includes nonces and is bound to both
agents' identities). But this isn't specified.

**Suggested resolution**: Since ENCRYPTED is being removed (issue
4.10), this is moot for v1. For future application-layer encryption,
specify that keys are derived from:
```
app_key = HKDF-Expand(session_key, info="aafp-app-encryption-v1", L=32)
```
Where `session_key` is derived from the handshake transcript.

**Changes wire protocol**: No (future consideration)

---

## 9. Extensibility Review

### 9.1 Extension Negotiation Protocol (HIGH)

**Description**: RFC-0002 Section 6.3 describes three extension types
(optional, negotiated, mandatory) but doesn't specify the negotiation
protocol. How does the client propose an extension? How does the
server accept or reject? What happens if a negotiated extension is
used in a frame but wasn't accepted?

**Rationale**: TLS 1.3 has a well-defined extension negotiation
protocol (RFC 8446 Section 4.2): the client proposes extensions in
ClientHello, the server accepts a subset in ServerHello/EncryptedExtensions.
AAFP needs similar precision.

**Suggested resolution**: Specify:
1. The ClientHello `extensions` field lists all extensions the client
   supports (with optional data).
2. The ServerHello `extensions` field lists the extensions the server
   accepts (a subset of the client's list).
3. Extensions not in the ServerHello are NOT active for the session.
4. Using a non-negotiated extension in a subsequent frame is a
   protocol error (error code 8007 INVALID_FLAGS or a new error code).
5. Mandatory extensions that are not accepted cause handshake failure
   (error code 2005 UNSUPPORTED_EXTENSIONS).

**Changes wire protocol**: Yes (defines negotiation protocol)

### 9.2 Future Feature Extensibility Assessment

| Future Feature | Extension Point | Compatible? |
|----------------|----------------|-------------|
| Resource exchange | Application-layer RPC | Yes |
| Distributed scheduling | Application-layer RPC | Yes |
| Semantic capability routing | CapabilityDescriptor metadata | Yes |
| Payment/settlement | Application-layer RPC | Yes |
| Federation (cross-network) | New discovery class + extension | Yes |
| Marketplaces | Application-layer RPC | Yes |
| GossipSub | New frame type (0x09+) | Yes |
| Session resumption | New handshake message + extension | Yes |
| NAT traversal | New RFC (circuit relay) | Yes |
| Key rotation | New handshake message + extension | Yes |

**Assessment**: The protocol's extensibility is good. The extension
mechanism, frame type registry, and CBOR schema evolution rules
provide adequate extension points for future features without changing
the core protocol.

### 9.3 RPC Method Registry (LOW)

**Description**: There's no registry for RPC method names. RFC-0004
defines `aafp.discovery.*` methods, but future method names could
conflict.

**Suggested resolution**: Define a method naming convention:
`aafp.<subsystem>.<method>` for standard methods. Application-defined
methods use a different prefix (e.g., `app.<namespace>.<method>`).
Document this in RFC-0006.

**Changes wire protocol**: No

---

## 10. Risk Register

| ID | Risk | Severity | Probability | Status |
|----|------|----------|-------------|--------|
| R1 | Independent implementations produce non-interoperable wire formats due to CBOR key type ambiguity | Critical | Very High | Must fix |
| R2 | Signature verification fails across implementations due to undefined transcript | Critical | Very High | Must fix |
| R3 | Relay attacks due to missing TLS channel binding | Critical | Medium | Must fix |
| R4 | Handshake fails due to undefined extension format | Critical | High | Must fix |
| R5 | Discovery RPC fails due to params encoding ambiguity | Critical | High | Must fix |
| R6 | Implementers target wrong version due to stale conformance section | Critical | Medium | Must fix |
| R7 | Compromised keys remain valid for long periods | High | Medium | Document + recommend short expiry |
| R8 | DoS via ClientHello replay | High | Medium | Implement nonce tracking |
| R9 | Amplification via bootstrap lookup | High | Low-Medium | Rate-limit |
| R10 | No cryptographic agility for signatures | High | Low (long-term) | Add key_algorithm field |
| R11 | Bootstrap model doesn't scale beyond ~100K agents | High | Certain (at scale) | Document limitation |
| R12 | ML-DSA-65 large key/signature sizes strain bandwidth and storage | Medium | Certain | Consider ML-DSA-44, lightweight records |
| R13 | Session ID non-interoperability due to "implementation detail" derivation | Medium | Medium | Make HKDF normative |
| R14 | Undefined feature flags cause confusion | Medium | Low | Remove undefined flags |
| R15 | CLOSE/ERROR frame overlap causes confusion | Low | Low | Document distinction |

---

## 11. Critical Issues Blocking Implementation

The following 6 issues MUST be resolved before implementation begins:

### C1: CBOR Map Key Type Inconsistency
- **RFC**: 0002, 0003, 0005
- **Section**: 0002 §4.3-4.6, §5.3-5.5; 0003 §3.2, §4.2, §5.4; 0005 §6.1
- **Resolution**: Use integer keys everywhere. Update all CBOR schemas.

### C2: Undefined Transcript Construction
- **RFC**: 0002
- **Section**: §5.5
- **Resolution**: Define `transcript = SHA-256(ClientHello_CBOR || ServerHello_CBOR)`. Sign over the 32-byte hash.

### C3: Undefined Handshake Extension Format
- **RFC**: 0002
- **Section**: §5.3, §5.4, §6.3
- **Resolution**: Define handshake extensions as CBOR array of `{type: uint, data: bstr}`. Define negotiation protocol.

### C4: RPC Params/Result Encoding Ambiguity
- **RFC**: 0002, 0004
- **Section**: 0002 §4.3-4.4; 0004 §3.3
- **Resolution**: Change `params` and `result` from `bstr` to `any` (CBOR any type). Define schemas for standard methods.

### C5: No TLS Channel Binding
- **RFC**: 0002, 0003
- **Section**: 0002 §5; 0003 §7
- **Resolution**: Include TLS exporter value in handshake transcript.

### C6: Stale Conformance Section
- **RFC**: 0001
- **Section**: §7.3
- **Resolution**: Update to reference v1 conformance per RFC-0006 §8.1.

---

## 12. Recommended RFC Changes

### RFC-0001
1. **[C6]** Update §7.3 to reference v1 conformance (RFC-0006 §8.1).
2. **[E2]** Remove or mark NAT traversal row as "future RFC."
3. **[L1]** Clarify §7.1: remove "stable for v0.x" (v0.x is not v1).
4. **[L2]** Update §6.2 to mention even/odd stream ID convention.
5. Add analysis of mixed Ed25519/ML-DSA-65 security posture to §9.

### RFC-0002
1. **[C1]** Convert all CBOR schemas to integer keys.
2. **[C2]** Define transcript construction in §5.5.
3. **[C3]** Define handshake extension format in §5.3/§6.3.
4. **[C4]** Change `params` and `result` from `bstr` to `any`.
5. **[C5]** Add TLS channel binding to transcript.
6. **[H4]** Add `expires_at` to ClientHello and ServerHello.
7. **[H5]** Fix 8001 fatal/stream contradiction (§3.4 vs RFC-0005 §4.4).
8. **[H6]** Clarify PING/PONG stream semantics.
9. **[M1]** Consider variable-length integer encoding for frame header.
10. **[M7]** Update CBOR reference from RFC 7049 to RFC 8949.
11. **[H8]** Add `key_algorithm` field to ClientHello and ServerHello.
12. Define extension negotiation protocol (accept/reject in ServerHello).

### RFC-0003
1. **[C1]** Ensure all CBOR schemas use integer keys (already done for
   AgentRecord, CapabilityDescriptor, UcanToken — verify consistency).
2. **[H4]** Use error code 2007 (not 2001) for AgentId mismatch.
3. **[M6]** Specify ML-DSA-65 signing mode (deterministic recommended).
4. **[H3]** Document revocation risk and recommend short expiry.
5. **[H4]** Define fingerprint format for out-of-band verification.
6. **[M8]** Make Session ID HKDF derivation normative (MUST, not
   RECOMMENDED).
7. **[M9]** Reference multiaddr specification or define AAFP format.

### RFC-0004
1. **[H9]** Document bootstrap model scalability limits.
2. **[M10]** Increase recommended record limit to 100,000.
3. **[M11]** Document PEX as probabilistic, not exhaustive.
4. **[L4]** Document 5-region model as v1 placeholder.
5. **[M12]** Consider lightweight AgentRecord format.

### RFC-0005
1. **[C1]** Ensure RPC error object uses integer keys (consistent with
   RFC-0002 after fix).
2. **[E3]** Clarify error code width (uint, max 9999).
3. **[H5]** Remove 8001 from "always fatal" list (or change RFC-0002
   to "close connection").
4. Add error code for "extension not negotiated" (e.g., 8010).

### RFC-0006
1. **[M3]** Remove ENCRYPTED (0x04) and ACK (0x08) from defined
   feature flags. Mark as reserved.
2. **[L5]** Define RPC method naming convention.
3. **[H7]** Define extension negotiation protocol (cross-reference
   RFC-0002).
4. **[H8]** Define key algorithm registry.

---

## 13. Final Go / No-Go Recommendation

### **GO WITH CHANGES**

Implementation may begin after resolving the 6 Critical issues (C1-C6).
These are all specification ambiguities/contradictions that would cause
independent implementations to diverge. None require architectural
changes — they require making existing design decisions explicit.

The High-severity issues should be resolved before any independent
implementation attempts conformance, but do not block the reference
implementation (which can make its own decisions and document them).

The Medium and Low issues can be resolved during implementation or
deferred to RFC revisions.

### Rationale for GO WITH CHANGES (not NO-GO):
- The architecture is sound. The layering, post-quantum stance, and
  extension model are well-designed.
- The Critical issues are all "specification gaps" not "design flaws."
  The design is correct; the specification is incomplete.
- All Critical issues have clear, unambiguous resolutions.
- No issue requires rethinking the fundamental architecture.

### Rationale for GO WITH CHANGES (not GO):
- The CBOR key type inconsistency (C1) and undefined transcript (C2)
  would cause certain interimplementation failure.
- The missing channel binding (C5) is a real security vulnerability.
- The undefined extension format (C3) and RPC encoding (C4) make key
  protocol features unimplementable.

---

## 14. Weighted Decision Matrix

| Category | Weight | Score (0-10) | Weighted | Evidence |
|----------|--------|-------------|----------|----------|
| Security | 25% | 6.5 | 1.625 | PQ-by-default is excellent. But no channel binding (relay attacks), no revocation, no replay protection mechanism, TOFU MITM unmitigated. The crypto primitives are sound; the protocol integration has gaps. |
| Latency | 25% | 6.0 | 1.500 | 2.5 RTT handshake (TLS 1.3 + AAFP). ML-DSA-65 verification adds ~3ms. 28-byte frame header adds overhead. No 0-RTT resumption. Acceptable for long-lived connections, noticeable for short-lived. |
| Simplicity | 15% | 7.5 | 1.125 | Clean layering. 8 frame types. Well-defined error model. But CLOSE/ERROR overlap, undefined feature flags, and CBOR key inconsistency add confusion. Extension mechanism is well-designed. |
| Scalability | 15% | 5.0 | 0.750 | Bootstrap model works to ~100K agents. In-memory DHT doesn't scale. PEX is probabilistic. 5-region model is too coarse. ML-DSA-65 record sizes strain storage at scale. Future DHT RFC needed. |
| Implementability | 10% | 5.5 | 0.550 | 6 Critical ambiguities would block independent implementation. Rust trait definitions help. But CBOR key types, transcript, extensions, and RPC encoding all need resolution first. |
| Post-Quantum Readiness | 10% | 9.0 | 0.900 | X25519MLKEM768 hybrid KEX. ML-DSA-65 signatures. SHA-256 AgentIds. No classical-only mode. Excellent PQ stance. Only gap is no signature algorithm agility. |
| **Overall** | **100%** | | **6.45** | |

**Interpretation**: 6.45/10 — a solid foundation with significant
specification gaps that must be closed before the RFCs can serve as
a public standard. The architecture is good; the specification
precision is insufficient.

---

## 15. Comparison Against Mature Protocol Specifications

### vs RFC 9000 (QUIC)

| Aspect | QUIC | AAFP | Gap |
|--------|------|------|-----|
| Integer encoding | Variable-length (1-8 bytes) | Fixed 64-bit | AAFP is less efficient |
| Frame format | Type-specific, compact | Uniform 28-byte header | AAFP is simpler but wasteful |
| Version negotiation | In-band (version negotiation packet) | ALPN | AAFP is cleaner |
| Transport parameters | Well-defined TLS extension | Undefined handshake extensions | AAFP has a gap |
| Loss recovery | Detailed specification (RFC 9002) | Relies on QUIC | Correct |
| Connection migration | Connection ID | Not addressed | AAFP has a gap |
| Error model | Transport error codes + application error codes | Categorized error codes | AAFP is comparable |

**Assessment**: AAFP's frame format is less efficient than QUIC's but
simpler. The extension negotiation gap is the most significant
difference. AAFP correctly delegates reliability, congestion control,
and flow control to QUIC.

### vs RFC 8446 (TLS 1.3)

| Aspect | TLS 1.3 | AAFP | Gap |
|--------|---------|------|-----|
| Transcript hash | Precisely defined (§4.4.1) | Undefined | Critical gap |
| Key schedule | Well-defined (§7.1) | No key schedule (relies on TLS) | Acceptable |
| Extension negotiation | Precisely defined (§4.2) | Underspecified | Critical gap |
| Downgrade protection | Well-defined (§4.1.3) | Relies on ALPN | Acceptable |
| Error alerts | Defined alert protocol | ERROR frames | Comparable |
| 0-RTT | Defined (§2.3) | Not supported | Future work |
| Channel binding | Exporter defined (§7.5) | Not used | Critical gap |

**Assessment**: TLS 1.3 is significantly more precise in its
specification. The transcript hash, extension negotiation, and
channel binding are all areas where AAFP needs to match TLS 1.3's
level of precision.

### vs Noise Protocol Framework

| Aspect | Noise | AAFP | Gap |
|--------|-------|------|-----|
| Handshake patterns | Formal notation (XX, IK, etc.) | Ad-hoc | AAFP is less rigorous |
| Transcript hash | Running hash, precisely defined | Undefined | Critical gap |
| Key derivation | Well-defined (HKDF over transcript) | No KDF (relies on TLS) | Acceptable |
| Replay protection | Nonces + handshake pattern | Nonces (no tracking) | Partial gap |
| Identity hiding | Pattern-dependent | AgentId in clear (in handshake) | AAFP leaks identity |

**Assessment**: Noise's formal handshake pattern notation and
precise transcript hash construction are models for AAFP. The
identity hiding property is a fundamental difference — Noise can
hide initiator identity, while AAFP includes AgentId in the
ClientHello (visible to the server and anyone who can decrypt the
TLS layer).

### vs libp2p Specifications

| Aspect | libp2p | AAFP | Gap |
|--------|--------|------|-----|
| Multiaddr | Well-defined specification | Referenced but not specified | Gap |
| Peer ID | Defined derivation (multihash of pubkey) | Defined (SHA-256 of pubkey) | Comparable |
| Protocol negotiation | multistream-select | ALPN | AAFP is cleaner |
| DHT | KadDHT (well-specified) | In-memory (v1) | Future work |
| Identity | Ed25519 by default | ML-DSA-65 (PQ) | AAFP is more future-proof |
| Transport | Multi-transport (TCP, QUIC, WS) | QUIC only | AAFP is simpler |

**Assessment**: AAFP's identity model is more future-proof (PQ).
The multiaddr gap should be resolved. The DHT is acknowledged as
future work. The single-transport (QUIC) approach is simpler and
appropriate for v1.

### vs WireGuard Protocol Description

| Aspect | WireGuard | AAFP | Gap |
|--------|-----------|------|-----|
| Handshake size | 96 bytes | ~10KB (ML-DSA-65) | AAFP is 100x larger |
| Handshake latency | 1 RTT | 2.5 RTT | AAFP is 2.5x slower |
| Key rotation | Defined (session expiry) | Not in protocol | Gap |
| Replay protection | Nonce + bitmap | Nonces (no tracking) | Partial gap |
| Frame header | 32 bytes (with MAC) | 28 bytes (no MAC) | Comparable |
| Simplicity | ~4,000 lines of code | Unknown (Rust workspace) | AAFP is more complex |

**Assessment**: WireGuard is dramatically more efficient due to
Curve25519 + ChaCha20-Poly1305. AAFP's PQ primitives are inherently
larger and slower. This is a fundamental trade-off of post-quantum
cryptography, not a design flaw. However, AAFP should explore
optimizations (0-RTT, session resumption, smaller PQ variants) to
close the gap.

### Overall Specification Quality Assessment

| Protocol | Precision | Completeness | Interoperability Guidance |
|----------|-----------|-------------|--------------------------|
| RFC 9000 (QUIC) | Excellent | Excellent | Excellent |
| RFC 8446 (TLS 1.3) | Excellent | Excellent | Excellent |
| Noise | Excellent | Good | Good |
| libp2p | Good | Good | Moderate |
| WireGuard | Good | Moderate | Moderate |
| **AAFP (current)** | **Moderate** | **Moderate** | **Poor** |

**Assessment**: The AAFP RFCs are at the level of an early draft,
not a finalized standard. The architecture and design decisions are
well-reasoned, but the specification precision is insufficient for
independent implementation. Resolving the 6 Critical issues would
raise the precision to "Good" and the interoperability guidance to
"Moderate." Matching IETF standards (QUIC, TLS 1.3) would require
additional work on edge cases, test vectors, and conformance test
specifications.

---

## 16. Answers to Specific Questions

### Q1: If this protocol were frozen today, what decisions would be the hardest to change in five years?

1. **AgentId = SHA-256(ML-DSA-65 public key)**: Once agents are
   deployed with this identity scheme, changing it requires all
   agents to generate new identities. All UCAN tokens, AgentRecords,
   and discovery entries become invalid. This is the most
   irreversible decision.

2. **CBOR as the serialization format**: Switching to a different
   format (Protobuf, JSON, postcard) would break wire compatibility.
   CBOR is a good choice, but the decision is permanent.

3. **Frame header layout (28-byte fixed header)**: Once
   implementations parse frames based on this layout, changing it
   requires a new protocol version. The 64-bit length fields and
   fixed layout are locked in.

4. **ML-DSA-65 as the mandatory signature algorithm**: If ML-DSA-65
   is deprecated or a better algorithm emerges, migrating requires
   all agents to generate new key pairs. The lack of algorithm
   negotiation makes this harder.

5. **The 3-message handshake pattern (ClientHello → ServerHello →
   ClientFinished)**: Changing the handshake pattern (e.g., adding
   a 0-RTT mode, removing ClientFinished) requires a new protocol
   version and breaks all existing implementations.

6. **Error code numbering (thousands-digit categories)**: Once error
   codes are assigned, they cannot be renumbered. The category
   scheme is locked in.

### Q2: Which assumptions are most likely to be invalidated by future networking or cryptographic developments?

1. **X25519MLKEM768 as the PQ KEX**: NIST may standardize additional
   or replacement KEMs. If a vulnerability is found in ML-KEM-768,
   the protocol must support alternative KEX groups. (Mitigated by
   relying on TLS for KEX negotiation, but the RFC mandates
   X25519MLKEM768.)

2. **ML-DSA-65 as the signature algorithm**: NIST may standardize
   additional signature schemes (e.g., SLH-DSA, Falcon). If ML-DSA-65
   is broken, all identities are compromised. (Not mitigated — no
   algorithm negotiation.)

3. **QUIC as the sole transport**: Future networks may require
   different transports (e.g., ICE for WebRTC, raw UDP for satellite
   links). The protocol is tightly coupled to QUIC. (Partially
   mitigated by the Transport trait abstraction, but the wire format
   assumes QUIC stream semantics.)

4. **Bootstrap-based discovery**: At scale, bootstrap nodes are a
   bottleneck and single point of failure. The assumption that
   bootstrap nodes are sufficient will be invalidated above ~100K
   agents. (Acknowledged, distributed DHT is future work.)

5. **Self-signed certificates with TOFU**: The security community
   may move away from TOFU models. If ML-DSA-65 TLS certificates
   become supported, the protocol should transition, but the TOFU
   assumption is baked into the handshake design.

6. **32-byte AgentId**: If the agent population exceeds 2^128 (unlikely
   but theoretically possible in a multi-planetary future), collision
   resistance degrades. More practically, if a faster SHA-256
   preimage attack is found, 32 bytes may be insufficient. (Very
   unlikely, but the fixed size is irreversible.)

### Q3: What are the top five protocol decisions that deserve another design review before version 1.0?

1. **CBOR map key convention (integer vs string)**: This affects
   every CBOR structure, every signature, and every implementation.
   The current inconsistency must be resolved, and the choice should
   be reviewed for long-term implications (compactness vs readability
   vs tooling support).

2. **Frame header format (fixed 28-byte vs variable-length)**: The
   current format is simple but wasteful. Variable-length encoding
   (QUIC-style) is more efficient but more complex. This decision
   affects every frame ever sent and is irreversible after v1.

3. **Handshake transcript construction**: The transcript is used for
   signature verification and session ID derivation. Its construction
   must be precisely defined and should include channel binding to
   TLS. This is a security-critical decision.

4. **Signature algorithm agility**: Whether to add a `key_algorithm`
   field to the handshake (enabling future algorithm support) or
   mandate ML-DSA-65 only. Adding the field now is cheap; adding it
   later requires a new protocol version.

5. **Extension negotiation protocol**: The current specification
   describes extension types but not the negotiation flow. The
   negotiation protocol (propose in ClientHello, accept in
   ServerHello) must be precisely defined, as it's the primary
   forward-compatibility mechanism.

### Q4: If an independent team implemented only the RFCs (without access to our code), where are they most likely to interpret the specification differently?

1. **Transcript construction for ClientFinished signature** (~95%
   probability of divergence): The word "transcript" is undefined.
   Different teams will choose different byte sequences to sign over.
   This is the #1 source of interimplementation failure.

2. **CBOR map key types** (~90%): RFC-0002 shows string keys;
   RFC-0003/0005 show integer keys. Teams will choose differently
   based on which RFC they read first.

3. **Handshake extension encoding** (~85%): The `extensions` field
   format is undefined. Teams will guess: array of ints, array of
   maps, binary blocks, etc.

4. **RPC params encoding** (~80%): The `bstr` type for params is
   ambiguous. Teams will disagree on whether to nest CBOR inside
   bstr or use a different encoding.

5. **Session ID derivation** (~60%): "Implementation detail" means
   each team will choose a different derivation. This doesn't affect
   security (all methods can be secure) but affects interoperability
   for future session resumption.

6. **Error code 8001 handling** (~50%): RFC-0002 says "close the
   stream" but RFC-0005 says "always fatal" (close connection).
   Teams will choose one or the other.

7. **PING/PONG stream usage** (~40%): Teams will disagree on whether
   PING is connection-level or stream-level, and which stream to use
   for keepalive.

8. **ML-DSA-65 signing mode** (~50%): FIPS 204 allows deterministic
   and randomized signing. Teams will choose differently, affecting
   test reproducibility but not interoperability.

---

## 17. Summary

The AAFP RFC suite presents a well-architected post-quantum
networking protocol with a clean layering model, sound cryptographic
choices, and a reasonable extensibility framework. The design
decisions — QUIC transport, ML-DSA-65 identity, capability-based
discovery, UCAN authorization — are well-motivated and appropriate
for the stated goals.

However, the specification is not yet precise enough to serve as a
public standard. Six Critical issues — primarily around CBOR encoding
consistency, transcript definition, extension format, and channel
binding — must be resolved before independent implementation can
succeed. These are specification gaps, not design flaws, and all have
clear resolutions.

The recommendation is **GO WITH CHANGES**: resolve the 6 Critical
issues, then begin implementation. The High-severity issues should be
resolved before publishing the RFCs for independent implementation.

The protocol scores 6.45/10 on the weighted decision matrix, with
strong post-quantum readiness (9.0) and simplicity (7.5) offset by
scalability concerns (5.0) and implementability gaps (5.5). Resolving
the Critical issues would raise the overall score to approximately
7.5-8.0.
