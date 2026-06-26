# AAFP Protocol Review (Second Pass): RFC-0001 through RFC-0006

```
Review Date:       2025-06-25 (second pass)
Reviewer Role:     Protocol Reviewer / Standards Editor / Distributed Systems
                   Architect / Cryptography Reviewer / Interoperability
                   Engineer / Adversarial Reviewer
Review Standard:   IETF / QUIC WG / libp2p maintainers level
RFCs Under Review: RFC-0001 through RFC-0006 (Draft)
Primary Sources:   RFC 8446 (TLS 1.3), RFC 9000 (QUIC), RFC 8949 (CBOR),
                   Noise Protocol Framework, libp2p/rust-libp2p,
                   quinn-rs/quinn, WireGuard protocol specification
Relation to REVIEW-0001: This is a second-pass review that leverages
                   primary source documents fetched via MCP tools.
                   It confirms findings from REVIEW-0001, identifies
                   new issues, and provides concrete resolution
                   patterns from mature protocols.
```

---

## 1. Executive Summary

This second-pass review was conducted by fetching and comparing
against primary source specifications: RFC 8446 (TLS 1.3) transcript
hash and exporter definitions, RFC 9000 (QUIC) variable-length integer
encoding, RFC 8949 (CBOR) deterministic encoding rules, the Noise
Protocol Framework's channel binding and handshake hash mechanisms,
libp2p's PeerId derivation and Noise identity binding, quinn/rustls's
TLS exporter and PQ KEX support, and WireGuard's DoS-protected
handshake.

The second pass **confirms all 6 Critical issues from REVIEW-0001**
and identifies **7 additional issues** not found in the first pass:

1. **No domain separation in signature computations** (HIGH) —
   libp2p-noise uses "noise-libp2p-static-key:" as a domain separator
   to prevent cross-protocol attacks. AAFP signs raw transcripts with
   no domain separation.

2. **AgentId uses raw SHA-256, not multihash** (MEDIUM) — libp2p's
   PeerId uses multihash, which encodes the hash function in the ID.
   AAFP's raw SHA-256 doesn't encode the hash function, making future
   hash changes harder.

3. **No DoS protection in handshake (mac1/mac2 equivalent)** (HIGH) —
   WireGuard uses mac1 (validates receiver's public key before
   expensive crypto) and mac2 (cookie-based proof-of-IP under load).
   AAFP has no equivalent. The ClientHello replay issue is more
   severe than initially rated.

4. **Transcript should be a running hash, not final concatenation**
   (MEDIUM) — Both TLS 1.3 and Noise use running hash constructions
   (`Hash(M1 || M2 || ... || Mn)` for TLS, `h = HASH(h || data)` for
   Noise). AAFP's undefined transcript should follow this pattern.

5. **Full public key in every handshake (10KB)** (MEDIUM) — WireGuard's
   handshake is 148 bytes. AAFP's is ~10KB due to ML-DSA-65. The
   public key could be referenced by AgentId and fetched from
   discovery, reducing handshake size by ~80%.

6. **libp2p signs the DH key, not the transcript** (INFORMATIONAL) —
   libp2p-noise signs the static DH public key (bound to the session)
   rather than the transcript hash. AAFP could sign the TLS exporter
   value (session-bound) instead of constructing a separate transcript,
   simplifying C2 and C5 into a single resolution.

7. **quinn exposes `export_keying_material()`** (INFORMATIONAL) —
   Confirmed that the TLS exporter API is available in the
   implementation stack, making channel binding (C5) straightforward
   to implement.

**Recommendation: GO WITH CHANGES** (confirmed from first pass)

**Weighted Score: 6.3/10** (slightly lower than first pass due to
newly identified issues; the architecture is sound but the
specification gaps are more numerous than initially assessed)

---

## 2. Primary Source Comparison

### 2.1 TLS 1.3 (RFC 8446) — Transcript Hash

**Source**: RFC 8446 Section 4.4.1 (fetched from rfc-editor.org)

TLS 1.3 defines the transcript hash precisely:

```
Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
```

Where each `Mi` includes the handshake message header (type + length
fields) but not record layer headers. The transcript is a running
hash — each message is appended to the previous hash state.

TLS 1.3 also defines the exporter (Section 7.5):

```
TLS-Exporter(label, context_value, key_length) =
    HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
                      "exporter", Hash(context_value), key_length)
```

**AAFP Gap**: The AAFP handshake transcript (RFC-0002 Section 5.5) is
undefined. TLS 1.3's precise definition — including message headers
in the transcript — is the standard approach. AAFP must define
whether the transcript includes frame headers or only CBOR payloads.

**Resolution Pattern**: AAFP should define:
```
transcript_hash = SHA-256(ClientHello_CBOR || ServerHello_CBOR)
```
Where `ClientHello_CBOR` and `ServerHello_CBOR` are the canonical
CBOR encodings of the handshake message maps (excluding signature
fields). This follows TLS 1.3's pattern of hashing message contents
but is simpler because AAFP messages don't have separate headers
(the frame header is not part of the handshake message).

### 2.2 Noise Protocol Framework — Channel Binding

**Source**: Noise Protocol Framework Section 11.2 (fetched from
noiseprotocol.org)

Noise defines channel binding via `GetHandshakeHash()`:

> "Parties can then sign the handshake hash, or hash it along with
> their password, to get an authentication token which has a
> 'channel binding' property: the token can't be used by the
> receiving party with a different session."

The handshake hash `h` is maintained as a running hash:
```
MixHash(data): Sets h = HASH(h || data)
```

**AAFP Gap**: AAFP has no channel binding. The AAFP handshake
signatures are over the handshake messages but not over the TLS
session, allowing relay attacks (REVIEW-0001 C5).

**Resolution Pattern**: AAFP should include the TLS exporter value
in the handshake transcript, following Noise's channel binding
pattern:
```
tls_binding = TLS-Exporter("aafp-channel-binding", "", 32)
transcript_hash = SHA-256(tls_binding || ClientHello_CBOR || ServerHello_CBOR)
ClientFinished.signature = ML-DSA-65.Sign(secret_key, transcript_hash)
```

This binds the AAFP session to the specific TLS channel, preventing
relay attacks. The TLS exporter is available in quinn via
`Connection::export_keying_material()` (confirmed via deepwiki query
of quinn-rs/quinn).

### 2.3 libp2p — PeerId Derivation and Identity Binding

**Source**: deepwiki query of libp2p/rust-libp2p

libp2p derives PeerId as:
```
PeerId = multihash(protobuf_encode(public_key))
```

For keys ≤42 bytes: identity multihash (key inlined, no hashing).
For keys >42 bytes: SHA-256 multihash.

The multihash format encodes the hash function code (0x00 for
identity, 0x12 for SHA-256) in the first 2 bytes, making the ID
self-describing.

libp2p-noise binds identity to the session by:
1. Signing the static DH public key with the identity keypair
2. Using a domain separator: "noise-libp2p-static-key:"
3. Signature is over `[STATIC_KEY_DOMAIN || dh_pubkey]`
4. Verification: `id_pk.verify([STATIC_KEY_DOMAIN, pubkey].concat(), sig)`

**AAFP Gaps**:

1. **AgentId = SHA-256(pubkey)** is not self-describing. If AAFP
   later switches to SHA-3 or BLAKE3, there's no way to distinguish
   old AgentIds from new ones. libp2p's multihash approach encodes
   the hash function in the ID.

2. **No domain separation**. AAFP signs raw CBOR maps with no domain
   separator. libp2p uses "noise-libp2p-static-key:" to prevent
   cross-protocol signature reuse. If an AAFP signature is ever used
   in another context that accepts ML-DSA-65 signatures over CBOR,
   it could be replayed.

**Resolution Patterns**:

1. **Multihash AgentId** (MEDIUM — changes wire protocol):
   ```
   AgentId = multihash(SHA-256, ML-DSA-65 public key)
   ```
   This encodes the hash function (0x12 for SHA-256) in the first
   2 bytes, followed by the 32-byte hash. Total: 34 bytes (2 bytes
   longer than current 32-byte AgentId). Future hash changes are
   identifiable from the AgentId itself.

   Alternatively, keep 32-byte AgentId but add a `hash_algorithm`
   field to the handshake (similar to `key_algorithm` from
   REVIEW-0001 issue 8.1).

2. **Domain separation** (HIGH — changes signature computation):
   ```
   signature = ML-DSA-65.Sign(secret_key,
       "aafp-v1-handshake" || transcript_hash)
   ```
   All AAFP signatures should be prefixed with a domain separator
   string. Different signature contexts use different separators:
   - Handshake: "aafp-v1-handshake"
   - AgentRecord: "aafp-v1-record"
   - UCAN token: "aafp-v1-ucan"

### 2.4 QUIC (RFC 9000) — Variable-Length Integer Encoding

**Source**: RFC 9000 Section 16 (fetched from rfc-editor.org)

QUIC uses variable-length integer encoding:

```
2MSB  Length  Usable Bits  Range
00    1       6            0-63
01    2       14           0-16383
10    4       30           0-1073741823
11    8       62           0-4611686018427387903
```

The 2 most significant bits of the first byte encode the length.
The integer value is encoded in the remaining bits, network byte
order.

**AAFP Gap**: AAFP uses fixed 64-bit fields for Stream ID, Payload
Length, and Extension Length (REVIEW-0001 issue 4.1). QUIC's
variable-length encoding would reduce the frame header from 28 bytes
to 4-16 bytes for most frames.

**Resolution Pattern**: Adopt QUIC's variable-length integer encoding
for Stream ID, Payload Length, and Extension Length. A PING frame
would have a 4-byte header (Version + FrameType + Flags + Reserved)
instead of 28 bytes. A 100-byte RPC request would have a ~10-byte
header instead of 28 bytes.

This is a wire protocol change but follows a proven IETF standard.

### 2.5 WireGuard — DoS-Protected Handshake

**Source**: WireGuard protocol specification (wireguard.com/protocol)

WireGuard's handshake includes two MACs for DoS protection:

- **mac1**: `MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])`
  - Validates that the sender knows the receiver's public key
  - Cheap to verify (MAC, not signature)
  - Always required

- **mac2**: `MAC(cookie, msg[0:offsetof(msg.mac2)])`
  - Cookie-based proof of IP ownership
  - Only required when server is under load
  - Cookie expires after 2 minutes
  - Cookie = MAC of sender's IP with rotating server secret

WireGuard's handshake initiation message is 148 bytes total. The
full handshake completes in 1-RTT (Noise_IK pattern with pre-known
static key).

**AAFP Gaps**:

1. **No cheap pre-verification**: AAFP's server must perform
   expensive ML-DSA-65 signature verification (~1ms) before it can
   reject invalid ClientHello messages. WireGuard's mac1 allows
   rejecting invalid messages with a cheap MAC verification.

2. **No cookie mechanism**: Under DoS load, AAFP has no way to
   require proof-of-IP before processing handshake messages.

3. **10KB handshake vs 148 bytes**: AAFP's ClientHello is ~10KB
   (ML-DSA-65 public key: 1952 bytes + signature: 3309 bytes +
   capabilities + extensions). WireGuard's is 148 bytes. The size
   difference is inherent to PQ cryptography, but AAFP could reduce
   it by referencing the public key by AgentId rather than including
   it inline.

**Resolution Patterns**:

1. **mac1 equivalent** (HIGH — changes wire protocol):
   Add a `receiver_mac` field to ClientHello:
   ```
   receiver_mac = HMAC-SHA256(
       key = HKDF(receiver_agent_id, "aafp-mac-key"),
       data = ClientHello_without_signature)
   ```
   The server can verify this cheaply (HMAC) before performing
   expensive ML-DSA-65 signature verification. If the MAC is
   invalid, the server rejects without verifying the signature.

2. **Cookie mechanism** (MEDIUM — future RFC):
   Defer to a future RFC but document the design pattern.

3. **Reference public key by AgentId** (MEDIUM — changes wire
   protocol):
   The ClientHello could include only the AgentId (32 bytes) rather
   than the full public key (1952 bytes). The server fetches the
   public key from discovery (DHT or cache). This reduces ClientHello
   size by ~2KB. However, this requires the server to have the
   client's AgentRecord, which may not be available for first
   connections. This should be optional: include the full key by
   default, allow omission if the server has cached the record.

### 2.6 RFC 8949 (CBOR) — Deterministic Encoding

**Source**: RFC 8949 Section 4.2 (fetched via web search)

RFC 8949 defines two deterministic encoding modes:

1. **Core deterministic encoding** (Section 4.2.1): Map keys sorted
   in bytewise lexicographic order of their deterministic encodings.

2. **Length-first core deterministic encoding** (Section 4.2.3):
   Map keys sorted such that shorter encodings come first, then
   bytewise lexicographic for same-length encodings. This is
   compatible with RFC 7049 Section 3.9 ("Canonical CBOR").

**AAFP Gap**: RFC-0002 Section 8.1 cites "RFC 7049 Section 3.9" but
describes "shortest encoding first, then lexicographic" which matches
RFC 8949 Section 4.2.3 (length-first), not RFC 7049. RFC 7049 has
been obsoleted by RFC 8949.

**Resolution**: Update all references from RFC 7049 to RFC 8949.
Specify "length-first core deterministic encoding requirements"
(RFC 8949 Section 4.2.3) as normative. This matches the existing
AAFP rules and is the most widely supported deterministic encoding.

### 2.7 quinn/rustls — Implementation Stack Confirmation

**Source**: deepwiki query of quinn-rs/quinn

Confirmed:
- `Connection::export_keying_material(label, context, key_length)`
  is available for TLS channel binding.
- `X25519MLKEM768` is supported with the `aws-lc-rs` backend.
- ALPN is configured via `alpn_protocols` field.
- Self-signed certificates work with custom `ServerCertVerifier`.
- `HandshakeData` includes `negotiated_key_exchange_group`.

**Impact**: All cryptographic mechanisms recommended in this review
(TLS exporter for channel binding, PQ KEX, ALPN negotiation) are
available in the implementation stack. No implementation blockers.

---

## 3. New Issues Found in Second Pass

### 3.1 No Domain Separation in Signatures (HIGH)

**Description**: All AAFP signatures (handshake, AgentRecord, UCAN)
are computed over raw CBOR-encoded data with no domain separator
prefix. libp2p-noise uses "noise-libp2p-static-key:" as a domain
separator to prevent cross-protocol signature reuse.

**Rationale**: Without domain separation, an AAFP signature over a
CBOR map could potentially be valid in another protocol that accepts
ML-DSA-65 signatures over CBOR maps with the same structure. Domain
separation ensures signatures are only valid in the AAFP context.

**Impact**: Cross-protocol signature reuse attack vector. Low
probability but high impact if exploited.

**Suggested resolution**: Prefix all signature inputs with a
domain separator:
- Handshake signatures: `"aafp-v1-handshake" || data`
- AgentRecord signatures: `"aafp-v1-record" || data`
- UCAN token signatures: `"aafp-v1-ucan" || data`

**Changes wire protocol**: Yes (signature computation changes)

### 3.2 No Handshake DoS Pre-Verification (HIGH)

**Description**: The server must perform expensive ML-DSA-65
signature verification (~1ms) before it can reject invalid
ClientHello messages. WireGuard uses a cheap MAC (mac1) to reject
invalid messages before expensive crypto operations.

**Rationale**: An attacker can send thousands of ClientHello messages
with invalid signatures, forcing the server to perform millions of
1ms signature verifications. WireGuard's mac1 allows rejecting these
with a cheap HMAC verification.

**Impact**: DoS amplification. 1KB ClientHello forces ~1ms CPU on
server. 10K requests/second = 10 seconds of CPU/second.

**Suggested resolution**: Add a `receiver_mac` field to ClientHello:
```
receiver_mac = HMAC-SHA256(
    key = HKDF-SHA256(receiver_agent_id, "aafp-receiver-mac", 32),
    data = canonical_CBOR(ClientHello_without_signature_and_receiver_mac))
```
The server verifies this MAC (cheap) before verifying the signature
(expensive). If the MAC is invalid, reject with error 2001.

**Changes wire protocol**: Yes (adds field to ClientHello)

### 3.3 AgentId Not Self-Describing (MEDIUM)

**Description**: AgentId = SHA-256(public_key) is a raw 32-byte hash
with no indication of the hash function used. libp2p's PeerId uses
multihash, which encodes the hash function code (0x12 for SHA-256)
in the first 2 bytes.

**Rationale**: If AAFP later switches to SHA-3-256 or BLAKE3 for
AgentId derivation, there's no way to distinguish old AgentIds
(SHA-256) from new ones (SHA-3-256). This makes hash function
migration difficult.

**Impact**: Long-term migration risk. Not a problem for v1 but
becomes critical if SHA-256 is weakened.

**Suggested resolution**: Two options:
1. Use multihash format: `AgentId = multihash(0x12, SHA-256(pubkey))`
   (34 bytes, self-describing).
2. Keep 32-byte AgentId but add `hash_algorithm` field to handshake
   (similar to `key_algorithm` from REVIEW-0001 issue 8.1).

Option 2 is simpler and doesn't change AgentId size. Option 1 is
more future-proof.

**Changes wire protocol**: Yes (either approach changes something)

### 3.4 Transcript Should Be Running Hash (MEDIUM)

**Description**: Both TLS 1.3 and Noise use running hash constructions
for transcripts. TLS: `Hash(M1 || M2 || ... || Mn)`. Noise:
`h = HASH(h || data)` after each message. AAFP's undefined transcript
should follow this established pattern.

**Rationale**: A running hash is more efficient (no need to store all
messages) and is the standard approach in mature protocols. A final
concatenation requires storing all messages and hashing them at once.

**Suggested resolution**: Define the transcript as a running SHA-256
hash:
```
h = SHA-256(tls_binding || ClientHello_CBOR)
h = SHA-256(h || ServerHello_CBOR)
transcript_hash = h
```
The ClientFinished signature is over `transcript_hash`.

**Changes wire protocol**: Yes (defines normative transcript —
same as REVIEW-0001 C2 but with running hash pattern)

### 3.5 Full Public Key in Every Handshake (MEDIUM)

**Description**: ClientHello and ServerHello include the full
ML-DSA-65 public key (1952 bytes). WireGuard's handshake is 148
bytes total. AAFP's ClientHello is ~10KB.

**Rationale**: The public key can be derived from the AgentId via
discovery (DHT, PEX, or cache). Including it in every handshake is
wasteful for repeated connections. However, for first connections,
the server may not have the client's AgentRecord.

**Impact**: 2KB overhead per handshake message. At 1M
handshakes/second, this is 2GB/s of unnecessary bandwidth.

**Suggested resolution**: Make the public key field optional in
ClientHello/ServerHello:
- If the peer has the AgentRecord (from discovery/cache), the public
  key field MAY be omitted.
- If the peer doesn't have the AgentRecord, the public key field
  MUST be included.
- The receiver verifies that the included AgentId matches
  SHA-256(public_key) if the key is included, or looks up the key
  from discovery if omitted.

**Changes wire protocol**: Yes (makes field optional)

### 3.6 No Identity Hiding (LOW)

**Description**: The ClientHello includes the AgentId in cleartext
(encrypted by QUIC, but visible to the server and anyone who can
decrypt the TLS layer). Noise patterns like XX offer identity
hiding (the initiator's static key is sent under encryption).

**Rationale**: In AAFP, the client's AgentId is sent before the
server is authenticated. A malicious server can collect AgentIds
of all connecting clients. Noise's XX pattern sends the initiator's
static key under encryption (after the first DH exchange).

**Impact**: Privacy concern. A malicious bootstrap node can
enumerate all connecting agents.

**Suggested resolution**: Document the privacy trade-off. For v1,
the AgentId must be sent in clear (the server needs it to look up
the AgentRecord). Future versions could use an ephemeral identity
for the initial handshake, with the real AgentId revealed after
mutual authentication.

**Changes wire protocol**: No (document for v1; future consideration)

### 3.7 CLOSE/ERROR Frame Overlap (LOW)

**Description**: CLOSE (0x05) and ERROR (0x06) frames both carry
error codes and human-readable messages. CLOSE is for connection
termination; ERROR is for error reporting. But a fatal ERROR frame
also triggers connection termination, making it functionally similar
to CLOSE.

**Rationale**: TLS 1.3 has a single alert protocol that handles both
error reporting and connection closure. QUIC has CONNECTION_CLOSE
frames that combine both. AAFP's separation is unusual.

**Impact**: Implementers may be confused about when to send CLOSE
vs ERROR. The protocol works but is more complex than necessary.

**Suggested resolution**: Document the distinction clearly:
- ERROR frame: Reports an error. May be fatal (connection closes)
  or non-fatal (connection continues).
- CLOSE frame: Graceful connection termination. May include an
  error code as the reason. Sent after all ERROR frames are
  processed.

Alternatively, merge them into a single frame type (like TLS/QUIC).
But this is a minor simplification and not worth the wire protocol
change for v1.

**Changes wire protocol**: No (documentation clarification)

---

## 4. Confirmation of REVIEW-0001 Findings

All 6 Critical issues from REVIEW-0001 are confirmed and strengthened
by primary source comparison:

### C1: CBOR Map Key Type Inconsistency — CONFIRMED
TLS 1.3 uses a presentation language with explicit field types. QUIC
uses variable-length integers with explicit field definitions. Neither
has the ambiguity that AAFP has with mixed string/integer CBOR keys.
**Must fix.**

### C2: Undefined Transcript Construction — CONFIRMED
TLS 1.3 defines transcript as `Hash(M1 || M2 || ... || Mn)` including
message headers (Section 4.4.1). Noise defines it as a running hash
`h = HASH(h || data)`. AAFP defines neither. **Must fix.** The
running hash pattern (Section 3.4 above) is the recommended resolution.

### C3: Undefined Handshake Extension Format — CONFIRMED
TLS 1.3 defines extensions precisely (Section 4.2): each extension
has a 2-byte type, 2-byte length, and variable-length data. AAFP's
handshake `extensions` field format is undefined. **Must fix.**

### C4: RPC Params/Result Encoding Ambiguity — CONFIRMED
TLS 1.3 and QUIC define each message type separately with explicit
field types. AAFP's `bstr` for RPC params is ambiguous. **Must fix.**

### C5: No TLS Channel Binding — CONFIRMED AND STRENGTHENED
Noise explicitly defines channel binding via `GetHandshakeHash()`
(Section 11.2). libp2p-noise binds identity to the session by signing
the DH static key. quinn exposes `Connection::export_keying_material()`.
The TLS exporter is the standard channel binding mechanism. **Must
fix.** The resolution is to include the TLS exporter value in the
transcript hash.

### C6: Stale Conformance Section — CONFIRMED
RFC-0001 §7.3 references v0.1; RFC-0006 §8.1 references v1. **Must
fix.**

---

## 5. Updated Security Threat Summary

| Threat | Status | Severity | New Info |
|--------|--------|----------|----------|
| Relay attack (no channel binding) | Unaddressed | Critical | Noise and libp2p both solve this; quinn has exporter API |
| Cross-protocol signature reuse | Unaddressed | High | NEW: libp2p uses domain separators |
| Handshake DoS (no pre-verification) | Unaddressed | High | NEW: WireGuard uses mac1/mac2 |
| ClientHello replay (DoS) | Partially mitigated | High | WireGuard's cookie mechanism is the standard solution |
| Key compromise (no revocation) | Unaddressed | High | Confirmed |
| TOFU MITM (no verification mechanism) | Partially mitigated | High | Confirmed |
| Amplification via bootstrap | Partially mitigated | High | Confirmed |
| AgentId hash function migration | Unaddressed | Medium | NEW: libp2p uses multihash (self-describing) |
| Sybil attacks | Unaddressed (deferred) | Medium | Confirmed |
| Metadata leakage | Partially mitigated | Medium | Confirmed |
| Session fixation | Partially mitigated | Medium | Confirmed |
| Identity hiding | Unaddressed | Low | NEW: Noise XX offers identity hiding; AAFP doesn't |
| Downgrade attacks | Mitigated | Low | Confirmed (ALPN protected by TLS) |
| Traffic analysis | Unaddressed (acceptable) | Low | Confirmed |

---

## 6. Updated Weighted Decision Matrix

| Category | Weight | Score (0-10) | Weighted | Evidence |
|----------|--------|-------------|----------|----------|
| Security | 25% | 6.0 | 1.500 | PQ-by-default excellent. But: no channel binding (relay attacks), no domain separation (cross-protocol reuse), no DoS pre-verification, no revocation, no replay tracking, TOFU MITM unmitigated. 4 unaddressed High-severity threats. |
| Latency | 25% | 5.5 | 1.375 | 2.5 RTT handshake (TLS 1.3 + AAFP). ML-DSA-65 verification ~3ms. 28-byte frame header. ~10KB handshake (vs WireGuard 148 bytes). No 0-RTT. No public key omission. |
| Simplicity | 15% | 7.0 | 1.050 | Clean layering. 8 frame types. Well-designed extension mechanism. But CLOSE/ERROR overlap, undefined feature flags, CBOR key inconsistency, and now domain separation and multihash considerations add complexity. |
| Scalability | 15% | 5.0 | 0.750 | Bootstrap model works to ~100K agents. In-memory DHT doesn't scale. 5-region model too coarse. ML-DSA-65 record sizes strain storage. ~6KB per AgentRecord. |
| Implementability | 10% | 5.0 | 0.500 | 6 Critical ambiguities block independent implementation. New issues (domain separation, DoS MAC, multihash) add more resolution work. But quinn/rustls stack confirmed to support all needed APIs. |
| PQ Readiness | 10% | 8.5 | 0.850 | X25519MLKEM768 hybrid KEX. ML-DSA-65 signatures. SHA-256 AgentIds. No classical-only mode. But: no signature algorithm agility, no hash function agility (raw SHA-256 vs multihash), no PQ KEX agility. |
| **Overall** | **100%** | | **6.03** | |

**Interpretation**: 6.03/10 — slightly lower than the first pass (6.45)
due to newly identified issues (domain separation, DoS pre-verification,
multihash, identity hiding). The architecture remains sound, but the
specification and security gaps are more numerous than initially
assessed. Resolving all Critical + High issues would raise the score
to ~7.5-8.0.

---

## 7. Updated Comparison Against Mature Protocol Specifications

### Specification Quality Assessment (with primary source comparison)

| Protocol | Precision | Completeness | Interop Guidance | AAFP Gap |
|----------|-----------|-------------|------------------|----------|
| RFC 8446 (TLS 1.3) | Excellent | Excellent | Excellent | Transcript undefined; no channel binding; no extension negotiation |
| RFC 9000 (QUIC) | Excellent | Excellent | Excellent | Fixed 64-bit fields vs variable-length; no DoS protection |
| Noise | Excellent | Good | Good | No running hash; no channel binding; no domain separation |
| libp2p | Good | Good | Moderate | Raw SHA-256 vs multihash; no domain separation |
| WireGuard | Good | Moderate | Moderate | 10KB handshake vs 148 bytes; no mac1/mac2 DoS protection |
| **AAFP (current)** | **Moderate** | **Moderate** | **Poor** | |

### Key Lessons from Primary Sources

1. **TLS 1.3**: Define the transcript hash precisely, including what
   is and isn't included. Use the TLS exporter for channel binding.

2. **QUIC**: Use variable-length integer encoding for compactness.
   Define frame types with explicit field layouts.

3. **Noise**: Use a running hash for the transcript. Expose the
   handshake hash for channel binding. Sign the handshake hash (or
   a session-bound value) for identity binding.

4. **libp2p**: Use multihash for self-describing identifiers. Use
   domain separation in signatures. Sign the session-bound key, not
   just the identity.

5. **WireGuard**: Include cheap pre-verification (MAC) before
   expensive crypto. Use cookies for DoS protection under load.
   Minimize handshake size.

---

## 8. Consolidated Issue List

### Critical (6 — from REVIEW-0001, all confirmed)

| ID | Issue | Wire Change | Resolution Pattern |
|----|-------|-------------|-------------------|
| C1 | CBOR map key type inconsistency | Yes | Use integer keys everywhere (TLS/QUIC use explicit types) |
| C2 | Undefined transcript construction | Yes | Running SHA-256 hash (TLS/Noise pattern) |
| C3 | Undefined handshake extension format | Yes | CBOR array of {type, data} (TLS extension pattern) |
| C4 | RPC params/result encoding ambiguity | Yes | Change bstr to any (or define nested CBOR) |
| C5 | No TLS channel binding | Yes | Include TLS exporter in transcript (Noise/libp2p pattern) |
| C6 | Stale conformance section | No | Update RFC-0001 §7.3 to reference v1 |

### High (12 — 10 from REVIEW-0001 + 2 new)

| ID | Issue | Wire Change | Source |
|----|-------|-------------|--------|
| H1 | No domain separation in signatures | Yes | NEW (libp2p pattern) |
| H2 | No handshake DoS pre-verification | Yes | NEW (WireGuard mac1 pattern) |
| H3 | Error code 2001 vs 2007 misuse | No | REVIEW-0001 |
| H4 | Missing expires_at in handshake | Yes | REVIEW-0001 |
| H5 | FRAME_TOO_LARGE fatal/stream contradiction | No | REVIEW-0001 |
| H6 | PING/PONG stream semantics | No | REVIEW-0001 |
| H7 | Signature computation ambiguity | Yes | REVIEW-0001 (resolved by C1) |
| H8 | No signature algorithm agility | Yes | REVIEW-0001 (add key_algorithm field) |
| H9 | Extension negotiation protocol undefined | Yes | REVIEW-0001 (TLS pattern) |
| H10 | No revocation mechanism | No | REVIEW-0001 (document + recommend short expiry) |
| H11 | TOFU MITM mitigation unspecified | No | REVIEW-0001 (define fingerprint format) |
| H12 | Amplification via bootstrap | No | REVIEW-0001 (rate-limit) |

### Medium (12 — 8 from REVIEW-0001 + 4 new)

| ID | Issue | Wire Change | Source |
|----|-------|-------------|--------|
| M1 | AgentId not self-describing (raw SHA-256) | Yes | NEW (libp2p multihash pattern) |
| M2 | Full public key in every handshake | Yes | NEW (WireGuard efficiency comparison) |
| M3 | Transcript should be running hash | Yes | NEW (TLS/Noise pattern) — subsumed by C2 |
| M4 | Frame header overhead (28 bytes) | Yes | REVIEW-0001 (QUIC variable-length pattern) |
| M5 | CBOR reference outdated (RFC 7049 → 8949) | No | REVIEW-0001 |
| M6 | ML-DSA-65 signing mode unspecified | No | REVIEW-0001 |
| M7 | Session ID derivation not normative | Yes | REVIEW-0001 (make HKDF normative) |
| M8 | Undefined feature flags (ENCRYPTED, ACK) | No | REVIEW-0001 (remove undefined) |
| M9 | Multiaddr format not specified | No | REVIEW-0001 |
| M10 | Bootstrap scalability limits | No | REVIEW-0001 |
| M11 | AgentRecord size at scale | Yes | REVIEW-0001 (lightweight record format) |
| M12 | No identity hiding | No | NEW (document for v1) |

### Low (5)

| ID | Issue | Wire Change | Source |
|----|-------|-------------|--------|
| L1 | CLOSE/ERROR frame overlap | No | NEW (document distinction) |
| L2 | AAFP vs QUIC stream ID confusion | No | REVIEW-0001 |
| L3 | Regional model too coarse | No | REVIEW-0001 |
| L4 | PEX scalability | No | REVIEW-0001 |
| L5 | RPC method registry | No | REVIEW-0001 |

### Editorial (3)

| ID | Issue | Source |
|----|-------|--------|
| E1 | Session ID circular reference | REVIEW-0001 |
| E2 | NAT traversal RFC missing | REVIEW-0001 |
| E3 | Error code width contradiction | REVIEW-0001 |

---

## 9. Final Go / No-Go Recommendation

### **GO WITH CHANGES** (confirmed)

Implementation may begin after resolving the 6 Critical issues (C1-C6)
and the 2 new High-severity issues (H1: domain separation, H2: DoS
pre-verification). The remaining High issues should be resolved before
independent implementation attempts conformance.

### Rationale

The architecture is sound. The post-quantum stance is excellent. The
layering is clean. But the specification has 6 Critical ambiguities
that would cause independent implementations to diverge, and 2 new
High-severity security gaps (domain separation, DoS pre-verification)
that are standard in mature protocols (libp2p, WireGuard).

All issues have clear resolution patterns from mature protocols:
- Transcript: TLS 1.3 / Noise running hash pattern
- Channel binding: TLS exporter / Noise GetHandshakeHash()
- Domain separation: libp2p-noise STATIC_KEY_DOMAIN pattern
- DoS pre-verification: WireGuard mac1 pattern
- Variable-length encoding: QUIC Section 16 pattern
- Self-describing IDs: libp2p multihash pattern
- Extension negotiation: TLS 1.3 Section 4.2 pattern

The implementation stack (quinn/rustls) supports all needed APIs
(exporter, PQ KEX, ALPN, self-signed certs).

---

## 10. Answers to Specific Questions

### Q1: If this protocol were frozen today, what decisions would be the hardest to change in five years?

1. **AgentId = SHA-256(ML-DSA-65 public key)** — All deployed
   identities, UCAN tokens, and discovery entries become invalid if
   this changes. The raw SHA-256 (without multihash) makes hash
   function migration especially painful (issue M1).

2. **CBOR as serialization format with integer/string key choice** —
   Once implementations parse frames, the key type is locked. The
   current inconsistency (C1) must be resolved before freezing.

3. **Frame header layout** — The 28-byte fixed header with 64-bit
   fields is inefficient but hard to change. QUIC's variable-length
   encoding (M4) should be adopted before freezing if efficiency
   matters.

4. **ML-DSA-65 as mandatory signature with no algorithm negotiation** —
   No `key_algorithm` field means no migration path (H8). This is
   the most risky long-term cryptographic decision.

5. **3-message handshake pattern** — Adding 0-RTT, removing
   ClientFinished, or adding DoS pre-verification (H2) all require
   new protocol versions once frozen.

6. **Domain separation strings** — Once signatures are computed with
   specific domain separators (H1), changing them invalidates all
   existing signatures.

### Q2: Which assumptions are most likely to be invalidated by future developments?

1. **X25519MLKEM768 as PQ KEX** — NIST may standardize replacement
   KEMs. Mitigated by relying on TLS for KEX negotiation, but the
   RFC mandates this specific group.

2. **ML-DSA-65 as sole signature algorithm** — NIST may standardize
   additional schemes. No algorithm negotiation (H8) blocks
   migration. SLH-DSA or Falcon may be preferred for different
   trade-offs.

3. **SHA-256 for AgentId** — If SHA-256 is weakened (unlikely but
   possible), raw SHA-256 AgentIds (M1) can't be distinguished from
   future hash-based IDs. Multihash would solve this.

4. **QUIC as sole transport** — Future networks (satellite, IoT)
   may need different transports. The wire format assumes QUIC
   stream semantics.

5. **Bootstrap-based discovery** — Above ~100K agents, bootstrap
   nodes are insufficient. The distributed DHT is future work but
   the protocol assumes bootstrap-first discovery.

6. **10KB handshake size is acceptable** — As agent density
   increases and connections become shorter, the 10KB handshake
   (vs WireGuard's 148 bytes) becomes a bottleneck. Public key
   omission (M2) would help.

### Q3: Top five protocol decisions deserving another design review before v1.0?

1. **CBOR map key convention (integer vs string)** — Affects every
   structure, every signature. Must be resolved and is irreversible
   after v1. (C1)

2. **Handshake transcript construction with channel binding** —
   Security-critical. Must include TLS exporter value and use
   running hash. Follows TLS 1.3 and Noise patterns. (C2, C5, M3)

3. **Domain separation in all signatures** — Prevents cross-protocol
   attacks. Follows libp2p pattern. Must be added before any
   signatures are computed. (H1)

4. **DoS pre-verification in handshake** — Standard in WireGuard.
   Without it, the protocol is vulnerable to cheap DoS attacks.
   (H2)

5. **Signature algorithm agility** — Add `key_algorithm` field now
   or lock to ML-DSA-65 forever. Adding later requires new protocol
   version. (H8)

### Q4: Where are independent implementers most likely to diverge?

1. **Transcript construction** (~95%): Undefined. TLS and Noise
   define this precisely; AAFP doesn't. Each team will choose a
   different byte sequence.

2. **CBOR map key types** (~90%): Contradictory between RFCs. Teams
   will choose based on which RFC they read first.

3. **Handshake extension encoding** (~85%): Undefined. Teams will
   guess different formats (array of ints, array of maps, binary
   blocks).

4. **RPC params encoding** (~80%): `bstr` is ambiguous. Teams will
   disagree on nested CBOR vs direct encoding.

5. **Domain separation** (~70%): NEW. If not specified, some teams
   will add domain separators and others won't, causing signature
   verification failures.

6. **Session ID derivation** (~60%): "Implementation detail" means
   each team chooses differently. Doesn't affect security but
   breaks future session resumption interoperability.

7. **DoS pre-verification** (~50%): NEW. If not specified, some
   teams will implement mac1-style protection and others won't,
   creating inconsistent DoS resistance.

8. **ML-DSA-65 signing mode** (~50%): FIPS 204 allows deterministic
   and randomized. Teams will choose differently.

---

## 11. Summary

The second-pass review, conducted with primary source comparison
against RFC 8446 (TLS 1.3), RFC 9000 (QUIC), RFC 8949 (CBOR), the
Noise Protocol Framework, libp2p, and WireGuard, confirms the
first-pass finding of **GO WITH CHANGES** with a slightly lower
score (6.03 vs 6.45) due to newly identified issues.

The new issues — domain separation (H1), DoS pre-verification (H2),
self-describing AgentId (M1), and public key omission (M2) — are all
addressed by established patterns in mature protocols. The
implementation stack (quinn/rustls) supports all needed APIs.

The 6 Critical issues from REVIEW-0001 remain the primary blockers.
Their resolutions are now backed by concrete primary source patterns:
- Transcript: TLS 1.3 Section 4.4.1 running hash
- Channel binding: Noise Section 11.2 + TLS exporter
- Extension negotiation: TLS 1.3 Section 4.2
- Domain separation: libp2p-noise STATIC_KEY_DOMAIN
- DoS protection: WireGuard mac1/mac2
- Variable-length encoding: QUIC Section 16

The protocol is architecturally sound and ready for implementation
after resolving the Critical and new High-severity issues.
