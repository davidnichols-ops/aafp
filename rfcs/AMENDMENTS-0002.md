# AMENDMENTS-0002: Cold-Read Review + Threat Model Amendments

**Date**: 2025-06-25
**Status**: Draft (pending approval gate)
**Source Reviews**: REVIEW-0003 (cold-read implementer), REVIEW-0004 (threat model)
**Scope**: Fixes for 4 CRITICAL interoperability bugs, 10 HIGH issues, and normative gaps from threat model

## Summary

Two independent reviews identified issues in the Freeze Candidate (Revision 2)
specification. The cold-read review found 4 CRITICAL interoperability bugs in
the handshake signature and transcript hash specification that would prevent
two independent implementations from interoperating. The threat model review
found that the trust model is not clearly articulated and key management
requirements are missing.

Per the freeze commitment (RFC-0006 Section 2.5), interoperability and
security issues discovered during freeze justify normative fixes. All
amendments below are classified as either interoperability fixes (required
for freeze) or normative gap closures (required before public deployment).

---

## A-C1: Unify Signature and Transcript Hash Model

**Source**: REVIEW-0003 C1, C4
**Severity**: CRITICAL (interoperability)
**RFCs Affected**: RFC-0002 §5.6, §5.7

### Problem

The signature formulas in RFC-0002 §5.6 do NOT use the running transcript
hash `h`. They use direct SHA-256 of concatenated values:

```
ClientHello.signature = Sign(sk, "aafp-v1-handshake" ||
    SHA-256(tls_binding || CH_CBOR_without_sig_and_mac))

ServerHello.signature = Sign(sk, "aafp-v1-handshake" ||
    SHA-256(tls_binding || CH_CBOR || SH_CBOR_without_sig))
```

But the transcript hash update steps compute:

```
h = SHA-256(tls_binding)                           // step 2
h = SHA-256(h || CH_CBOR_without_sig_and_mac)      // step 3
h = SHA-256(h || SH_CBOR_without_sig)              // step 4
```

The signature hashes `tls_binding || CH_CBOR`, but the transcript hashes
`SHA-256(tls_binding) || CH_CBOR`. These produce different results.
An implementer following the transcript hash description would compute
signatures over different bytes than an implementer following the explicit
formulas.

### Amendment

Adopt the TLS 1.3 model: **every signature signs over the running transcript
hash AFTER the current message is added**. This is the single source of truth
for signature inputs. The explicit concatenation formulas are removed.

**New §5.6 Transcript Hash and Signature Computation:**

```
1. After TLS handshake completion, both sides compute:
   tls_binding = TLS-Exporter("EXPORTER-AAFP-Channel-Binding", "", 32)

2. Initialize the transcript hash:
   h = SHA-256(tls_binding)

3. ClientHello phase:
   a. Construct ClientHello without signature (key 7) and receiver_mac (key 9).
   b. Compute CH_CBOR = canonical_CBOR(ClientHello_without_sig_and_mac).
   c. Update: h = SHA-256(h || CH_CBOR).
   d. ClientHello.signature = ML-DSA-65.Sign(
          secret_key,
          "aafp-v1-handshake" || h)
   e. Insert signature into ClientHello (key 7).
   f. Send ClientHello.

   Receiver (server):
   a. Receive ClientHello.
   b. Extract CH_CBOR = canonical_CBOR(ClientHello_without_sig_and_mac).
   c. Update: h = SHA-256(h || CH_CBOR).
   d. Verify ClientHello.signature against h.

4. ServerHello phase:
   a. Construct ServerHello without signature (key 8).
   b. Compute SH_CBOR = canonical_CBOR(ServerHello_without_sig).
   c. Update: h = SHA-256(h || SH_CBOR).
   d. ServerHello.signature = ML-DSA-65.Sign(
          secret_key,
          "aafp-v1-handshake" || h)
   e. Insert signature into ServerHello (key 8).
   f. Send ServerHello.

   Receiver (client):
   a. Receive ServerHello.
   b. Extract SH_CBOR = canonical_CBOR(ServerHello_without_sig).
   c. Update: h = SHA-256(h || SH_CBOR).
   d. Verify ServerHello.signature against h.

5. ClientFinished phase:
   a. Construct ClientFinished without signature (key 2).
   b. Compute CF_CBOR = canonical_CBOR(ClientFinished_without_sig).
   c. Update: h = SHA-256(h || CF_CBOR).
   d. ClientFinished.signature = ML-DSA-65.Sign(
          secret_key,
          "aafp-v1-handshake" || h)
   e. Insert signature into ClientFinished (key 2).
   f. Send ClientFinished.

   Receiver (server):
   a. Receive ClientFinished.
   b. Extract CF_CBOR = canonical_CBOR(ClientFinished_without_sig).
   c. Update: h = SHA-256(h || CF_CBOR).
   d. Verify ClientFinished.signature against h.

6. The final transcript hash h (after step 5c) is used for:
   - Session ID derivation (Section 5.7)
```

**Key principle**: The signature is ALWAYS computed over
`"aafp-v1-handshake" || h` where `h` is the transcript hash AFTER the current
message's CBOR has been folded in. The signature is never computed over raw
concatenations of tls_binding and message bytes.

**Verification ordering**: The receiver ALWAYS updates the transcript hash
BEFORE verifying the signature. This ensures both sides have the same `h`
value at verification time.

---

## A-C2: Define Canonical CBOR for Signature Inputs

**Source**: REVIEW-0003 C2
**Severity**: CRITICAL (interoperability)
**RFCs Affected**: RFC-0002 §5.6, §8.1

### Problem

When computing `canonical_CBOR(ClientHello_without_signature_and_receiver_mac)`,
it is unclear whether this means:
- (a) Encode a new map with only the included fields (keys 1-6, 8, 10)
- (b) Encode the full map then remove bytes for keys 7 and 9
- (c) Some other procedure

These produce different CBOR encodings (different map lengths, different
byte layouts), causing signature verification failures.

### Amendment

Add the following normative text to RFC-0002 §5.6:

> **Signature Input Encoding**: When a signature input specification says
> `canonical_CBOR(Message_without_field_X)`, this means:
>
> 1. Construct a NEW CBOR map containing exactly the fields of the message
>    EXCLUDING the specified field(s).
> 2. Encode this map using canonical CBOR (Section 8.1).
> 3. The resulting byte sequence is the signature input component.
>
> The excluded fields are omitted entirely — they are not present in the
> map, not encoded as null, and not encoded with zero-length values. The
> map length reflects only the included fields.
>
> For example, `canonical_CBOR(ClientHello_without_signature_and_receiver_mac)`
> produces a CBOR map with 8 entries (keys 1, 2, 3, 4, 5, 6, 8, 10),
> encoded in canonical form. Keys 7 (signature) and 9 (receiver_mac) are
> absent from the map.

---

## A-C3: Add Critical Bit to Handshake ExtensionEntry

**Source**: REVIEW-0003 C3
**Severity**: CRITICAL (interoperability)
**RFCs Affected**: RFC-0002 §6.4

### Problem

The handshake `ExtensionEntry` structure has no "critical" field, but the
negotiation rules (§6.4 rule 4) reference "mandatory extension". There is
no way for a client to indicate that a proposed handshake extension is
mandatory vs optional.

### Amendment

Add a `critical` field (boolean, key 3) to the handshake ExtensionEntry:

```cbor
ExtensionEntry = {
    1: uint,       // "type": Extension type (see RFC-0006 registry)
    2: bstr,       // "data": Extension-type-specific data
    3: bool,       // "critical": If true, the extension is mandatory.
                   //   If the server does not accept it, the handshake
                   //   MUST fail with error 2005.
                   //   If false, the extension is optional and the
                   //   server MAY silently drop it.
}
```

Update negotiation rule 4:

> 4. If the client proposed an extension with `critical = true` and the
>    server did not accept it (did not include it in ServerHello.extensions),
>    the server MUST send an ERROR frame with code 2005
>    (UNSUPPORTED_EXTENSIONS) and close the connection. If `critical = false`,
>    the server MAY silently drop the extension.

Update the integer key mapping table (§8.4) to include:
`ExtensionEntry | 3 | critical`

---

## A-H1: Clarify Extension Section Encoding

**Source**: REVIEW-0003 H1
**Severity**: HIGH
**RFCs Affected**: RFC-0002 §6.1

### Problem

§6.1 describes extension encoding but doesn't clarify that multiple
extensions are concatenated directly within the Extensions section.

### Amendment

Add to §6.1:

> Multiple extensions are concatenated directly within the Extensions
> section of the frame body. Each extension is self-delimiting via its
> Extension Data Length field. There is no additional framing between
> extensions. The total size of all extensions MUST equal the Extension
> Length field in the frame header.
>
> Example with two extensions:
> ```
> [Ext1.Type:2][Ext1.Critical:1][Ext1.Reserved:1][Ext1.DataLen:4][Ext1.Data:N]
> [Ext2.Type:2][Ext2.Critical:1][Ext2.Reserved:1][Ext2.DataLen:4][Ext2.Data:M]
> ```

Also clarify that the Extension Data Length field is 32 bits, big-endian
unsigned integer (consistent with all other multi-byte fields in the frame).

---

## A-H2: Clarify Extension Parameter Negotiation

**Source**: REVIEW-0003 H2
**Severity**: HIGH
**RFCs Affected**: RFC-0002 §6.4

### Problem

§6.4 says "server MAY include extension data that differs from the client's
proposal" but doesn't explain how parameter negotiation works.

### Amendment

Add to §6.4:

> #### Parameter Negotiation
>
> When a client proposes an extension, the extension data (key 2) contains
> the client's proposed parameters. When the server accepts the extension,
> the server's extension data (key 2) contains the server's selected
> parameters, which MAY differ from the client's proposal.
>
> The semantics of parameter negotiation are extension-type-specific. The
> extension specification MUST define:
> - What parameters the client proposes
> - What parameters the server may select
> - Whether the server must select a subset of the client's proposal or
>   may choose independently
>
> Example (hypothetical max-frame-size extension, type 0x0003):
> - Client proposes: data = CBOR uint 1048576 (1 MiB)
> - Server selects: data = CBOR uint 262144 (256 KiB)
> - Both sides use 256 KiB as the maximum frame size for the session.

---

## A-H3: Clarify Domain Separator Encoding

**Source**: REVIEW-0003 H3
**Severity**: HIGH
**RFCs Affected**: RFC-0003 §3.5

### Problem

The domain separator is described as "a UTF-8 string, NOT length-prefixed"
but it's unclear whether this includes a null terminator or how exactly the
bytes are concatenated.

### Amendment

Replace the relevant paragraph in RFC-0003 §3.5 with:

> The domain separator is encoded as its raw UTF-8 code units (bytes).
> No null terminator, no length prefix, and no CBOR encoding is applied.
> The signature input is the raw byte concatenation:
>
> ```
> sig_input = domain_separator_utf8_bytes || message_bytes
> ```
>
> For example, the domain separator `"aafp-v1-handshake"` is the 17-byte
> UTF-8 sequence (no null terminator):
> `0x61 0x61 0x66 0x70 0x2D 0x76 0x31 0x2D 0x68 0x61 0x6E 0x64 0x73 0x68
> 0x61 0x6B 0x65`

---

## A-H4: Clarify Integer Key Sorting in Canonical CBOR

**Source**: REVIEW-0003 H4
**Severity**: HIGH
**RFCs Affected**: RFC-0002 §8.1

### Problem

§8.1 says "Map keys are sorted by length-first canonical byte ordering" but
all AAFP maps use integer keys. The sort order for CBOR-encoded integers
needs clarification.

### Amendment

Replace rule 1 in §8.1 with:

> 1. Map keys are sorted by the length-first canonical byte ordering of
>    their CBOR encoding, as specified in RFC 8949 Section 4.2.3. This
>    means:
>    - Keys with shorter CBOR encodings come before keys with longer
>      encodings.
>    - Within the same encoding length, keys are sorted bytewise
>      lexicographically.
>
>    For integer keys (CBOR major type 0 or 1):
>    - Integers 0–23: encoded as 1 byte. Sorted numerically.
>    - Integers 24–255: encoded as 2 bytes (0x18 prefix + value).
>      Sorted by value, which is the same as bytewise order.
>    - All 1-byte keys sort before all 2-byte keys.
>
>    Example: keys 1, 2, 5, 10 sort as 1, 2, 5, 10 (all 1-byte).
>    Example: keys 1, 24, 100 sort as 1 (1-byte), then 24, 100 (2-byte).

---

## A-H5: Specify Stream 0 Lifecycle

**Source**: REVIEW-0003 H5
**Severity**: HIGH
**RFCs Affected**: RFC-0002 §5.2, §7.1

### Problem

The specification doesn't say whether stream 0 remains open or should be
closed after the handshake completes.

### Amendment

Add to §5.2 (after handshake completion description):

> Stream 0 remains open for the lifetime of the connection after the
> handshake completes. It is used for connection-level frames:
> - PING / PONG frames (Section 4.7)
> - GOAWAY frames (Section 4.8)
> - ERROR frames with fatal severity (RFC-0005 Section 4.4)
>
> Stream 0 MUST NOT be used for DATA frames or RPC frames after the
> handshake. Application data flows on streams ≥ 4 (client-initiated)
> or ≥ 5 (server-initiated).

---

## A-H6: Specify Transcript Hash Update Timing

**Source**: REVIEW-0003 H6
**Severity**: HIGH (subsumed by A-C1)
**RFCs Affected**: RFC-0002 §5.6

### Problem

The original spec doesn't specify whether the transcript hash is updated
before or after signature computation.

### Amendment

This is fully resolved by A-C1, which specifies the exact ordering:
- **Sender**: construct message → compute CBOR → update transcript hash →
  compute signature → insert signature → send.
- **Receiver**: receive message → extract CBOR → update transcript hash →
  verify signature.

No additional amendment needed beyond A-C1.

---

## A-M1: Resolve Session ID Circular Dependency

**Source**: Analysis during A-C1 review
**Severity**: HIGH (discovered during amendment drafting)
**RFCs Affected**: RFC-0002 §5.7

### Problem

The current spec says session_id is in ServerHello (key 7) and is derived
from the "final transcript hash h" (after ServerHello). But ServerHello
contains session_id, creating a circular dependency: the server cannot
compute session_id before constructing ServerHello if session_id derivation
requires the transcript hash that includes ServerHello.

### Amendment

Derive session_id from the transcript hash AFTER ClientHello (h_ch), not
after ServerHello. The server knows h_ch (it received ClientHello) and
both nonces (client's from ClientHello, its own) before constructing
ServerHello.

**New §5.7:**

```
session_id = HKDF-Extract(
    salt = client_nonce || server_nonce,
    IKM  = h_after_clienthello)

session_id = HKDF-Expand(
    prk  = above_extract,
    info = "aafp-session-id-v1",
    L    = 32)
```

Where:
- `h_after_clienthello` is the transcript hash after step 3c of §5.6
  (after ClientHello CBOR is folded in, before ServerHello).
- `client_nonce` is the 32-byte nonce from ClientHello (key 4).
- `server_nonce` is the 32-byte nonce from ServerHello (key 4).
- Nonce concatenation order: client_nonce first, then server_nonce.
- HKDF uses SHA-256 as the hash function.
- The `info` string is UTF-8 bytes (no null terminator).

The server computes session_id before constructing ServerHello and
includes it in ServerHello (key 7). The client computes session_id
after receiving ServerHello (it needs the server's nonce) and MUST
verify that the session_id in ServerHello matches its independently
derived value. If they differ, the client MUST send an ERROR frame
with code 2006 (HANDSHAKE_FAILED) and close the connection.

The session_id is bound to:
- The TLS channel binding (via h_after_clienthello)
- The ClientHello content (agent_id, public_key, capabilities, extensions)
- Both agents' nonces

It is NOT directly bound to ServerHello content, but the ServerHello
signature covers the full transcript (which includes ServerHello), and
the ClientFinished signature covers the full transcript including
ClientFinished. This provides end-to-end binding.

---

## A-M2: Resolve CapabilityDescriptor Metadata Key Type Contradiction

**Source**: REVIEW-0003 M4
**Severity**: MEDIUM
**RFCs Affected**: RFC-0002 §8.1, RFC-0003 §4.5

### Problem

RFC-0002 §8.1 says "All CBOR maps use integer keys (not string keys)" but
RFC-0003 §4.5 describes a metadata map using "BTreeMap ordering
(lexicographic key ordering)" with string keys.

### Amendment

Clarify in RFC-0003 §4.5 that the metadata map is an exception to the
integer-key rule. The metadata map uses text string keys (CBOR major type 3)
because keys are application-defined and not known at specification time.

Add to RFC-0002 §8.1:

> **Exception**: The CapabilityDescriptor metadata map (RFC-0003 §4.5)
> uses text string keys (CBOR major type 3), not integer keys. This is
> because metadata keys are application-defined and cannot be pre-assigned
> integer values. String keys in the metadata map are sorted by length-first
> canonical byte ordering of their UTF-8 encoding, consistent with RFC 8949
> §4.2.3. All other AAFP CBOR maps use integer keys.

---

## A-M3: Clarify DoS MAC Input

**Source**: REVIEW-0003 M9
**Severity**: MEDIUM
**RFCs Affected**: RFC-0002 §5.8

### Problem

The receiver_mac computation uses `canonical_CBOR(ClientHello_without_signature_and_receiver_mac)`
but doesn't clarify the relationship to the transcript hash input.

### Amendment

Add to §5.8:

> The `canonical_CBOR(ClientHello_without_signature_and_receiver_mac)` used
> for the receiver_mac computation is the same byte sequence as `CH_CBOR`
> used in the transcript hash (§5.6 step 3b). This is the canonical CBOR
> encoding of a map with keys 1, 2, 3, 4, 5, 6, 8, 10 (excluding keys 7
> and 9), per the signature input encoding rules (§5.6, A-C2).

---

## A-T1: Add Trust Model Section to RFC-0001

**Source**: REVIEW-0004 TH1
**Severity**: HIGH
**RFCs Affected**: RFC-0001 §9

### Amendment

Add a new subsection §9.0 (before §9.1) to RFC-0001:

> ### 9.0 Trust Model
>
> AAFP v1 uses a **decentralized trust model** with no trusted third
> parties. The following trust assumptions apply:
>
> **Trust Anchor**: Each agent's trust anchor is its own ML-DSA-65 secret
> key. There is no certificate authority, no public key infrastructure,
> and no trusted directory service in v1.
>
> **Self-Attested Identity**: All identity claims are self-attested.
> AgentRecords are self-signed (RFC-0003 §3.4). The `expires_at` field
> is self-attested by the key holder.
>
> **Bootstrap Node Trust**: Bootstrap nodes are trusted by configuration
> (out-of-band). The protocol does not verify bootstrap node identity or
> honesty. Implementations MUST support configuring multiple bootstrap
> nodes (see A-T3) to mitigate compromise of any single bootstrap node.
>
> **TLS Trust**: TLS certificates are self-signed with trust-on-first-use
> (TOFU). The application-layer handshake provides identity verification
> independent of TLS certificate validation.
>
> **Out-of-Band Verification Required For**:
> - First connection to a new agent (AgentId fingerprint verification,
>   see RFC-0003 §2.6)
> - Bootstrap node configuration
> - Revocation checking (if required by threat model)
>
> **NOT Trusted in v1**:
> - No CA or PKI
> - No revocation authority
> - No reputation system
> - No Sybil resistance mechanism
>
> Future versions MAY introduce trusted third parties or delegation-based
> trust, but v1 is fully decentralized.

---

## A-T2: Strengthen AgentId Fingerprint Requirements

**Source**: REVIEW-0004 TH4
**Severity**: HIGH
**RFCs Affected**: RFC-0003 §2.6

### Amendment

Change RFC-0003 §2.6 from:

> Implementations SHOULD display the fingerprint when a new agent
> connection is established and provide an API for applications to
> retrieve and compare fingerprints.

To:

> Implementations MUST display the AgentId fingerprint when a new agent
> connection is established (first connection to an unknown AgentId).
> Implementations MUST provide an API for applications to retrieve and
> compare fingerprints programmatically.
>
> The fingerprint display MUST occur before the application begins
> exchanging sensitive data with the new agent. Applications MAY
> override this requirement if they perform their own out-of-band
> identity verification.
>
> Rationale: The TOFU model is vulnerable to man-in-the-middle attacks
> on first connection. Mandatory fingerprint display ensures users have
> the opportunity to detect MITM by comparing fingerprints through a
> trusted channel (e.g., voice, QR code, pre-shared configuration).

---

## A-T3: Strengthen Key Compromise Documentation

**Source**: REVIEW-0004 TC1
**Severity**: CRITICAL
**RFCs Affected**: RFC-0003 §8.4

### Amendment

Replace RFC-0003 §8.4 with:

> ### 8.4 Key Compromise and Revocation
>
> #### Blast Radius
>
> If an agent's ML-DSA-65 secret key is compromised:
>
> 1. The attacker can impersonate the agent to all peers.
> 2. The attacker can sign AgentRecords and UCAN tokens.
> 3. The attacker can delegate capabilities to other agents.
> 4. The attacker can advertise false capabilities in the DHT.
> 5. **Existing sessions are NOT compromised**: they use TLS-derived
>    session keys, not ML-DSA-65 keys. Active sessions remain secure
>    until they expire or are closed.
> 6. **Past sessions are NOT compromised**: TLS 1.3 provides forward
>    secrecy for transport-layer traffic. However, if the attacker
>    recorded handshake messages, they can verify (but not forge)
>    past signatures.
> 7. **Application-layer identity has NO forward secrecy**: The
>    attacker can forge AgentRecords and UCAN tokens with past
>    timestamps (subject to `expires_at` validation by verifiers).
>
> #### Compromise Response
>
> Compromised agents MUST:
> 1. Generate a new ML-DSA-65 key pair.
> 2. Publish a new AgentRecord with the new public key and a new
>    AgentId.
> 3. Notify known peers out-of-band of the key rotation.
> 4. Revoke all UCAN tokens signed by the compromised key (by not
>    renewing them and waiting for expiry).
>
> #### Revocation (v1 Limitation)
>
> AAFP v1 does NOT provide an in-protocol revocation mechanism. A
> compromised key remains valid until the AgentRecord's `expires_at`
> timestamp. This is a known limitation.
>
> To mitigate the impact of key compromise:
>
> 1. Implementations MUST support AgentRecord expiry no longer than
>    30 days (2,592,000 seconds). Implementations MUST warn users if
>    an AgentRecord's `expires_at` exceeds 30 days from the current
>    time.
> 2. Implementations SHOULD renew AgentRecords every 7 days to keep
>    the expiry window short.
> 3. The `expires_at` field in the handshake (RFC-0002 §5.3, §5.4)
>    allows peers to verify expiry without discovery lookup.
> 4. Applications SHOULD implement out-of-band revocation checking
>    (e.g., a revocation list published out-of-band) if the threat
>    model requires it.
>
> #### Future Revocation Mechanism
>
> A future RFC will specify a revocation mechanism (see RFC-0006
> future work registry). The `key_algorithm` field and the extension
> mechanism provide the foundation for future revocation extensions.

---

## A-T4: Add Key Storage Requirements

**Source**: REVIEW-0004 TC2, TH8
**Severity**: CRITICAL
**RFCs Affected**: RFC-0003 §8

### Amendment

Add a new subsection §8.6 to RFC-0003:

> ### 8.6 Key Management Requirements
>
> #### Key Generation
>
> ML-DSA-65 key pairs MUST be generated using the algorithm specified
> in FIPS 204, using a cryptographically secure random number generator.
> Implementations SHOULD use hedged (randomized) signing as specified
> by FIPS 204 for side-channel resistance.
>
> #### Key Storage
>
> Implementations MUST protect ML-DSA-65 secret keys at rest using
> encryption. Implementations SHOULD use hardware-backed key storage
> (e.g., HSM, TPM, Secure Enclave) when available.
>
> Secret keys MUST NOT be logged, transmitted in plaintext, or stored
> in world-readable files. Implementations MUST zeroize secret key
> material from memory when no longer needed.
>
> #### Key Rotation
>
> AAFP v1 does not provide an in-protocol key rotation mechanism (see
> §2.5). Key rotation produces a new AgentId, requiring out-of-band
> notification to peers. Applications that require key rotation SHOULD:
>
> 1. Generate the new key pair before retiring the old key.
> 2. Publish the new AgentRecord before notifying peers.
> 3. Notify peers out-of-band of the new AgentId.
> 4. Maintain the old key until all known peers have migrated.
>
> A future RFC will specify an in-protocol key rotation mechanism.
>
> #### Key Compromise Detection
>
> Implementations SHOULD provide mechanisms to detect key compromise,
> such as:
> - Monitoring for unexpected AgentRecord publications
> - Alerting on connections from unexpected IP addresses
> - Logging all signing operations for audit
>
> These mechanisms are application-specific and not normatively
> specified in AAFP v1.

---

## A-T5: Strengthen Bootstrap Node Requirements

**Source**: REVIEW-0004 TH2
**Severity**: HIGH
**RFCs Affected**: RFC-0004 §3.1, §8.4

### Amendment

Add to RFC-0004 §3.1:

> Implementations MUST support configuring multiple bootstrap nodes.
> Implementations SHOULD use at least 3 bootstrap nodes from different
> administrative domains to mitigate eclipse attacks and bootstrap
> node compromise.

Add to RFC-0004 §8.4:

> #### Bootstrap Node Compromise
>
> If a bootstrap node is compromised:
>
> 1. **Eclipse attack**: The bootstrap node can return only attacker-
>    controlled peers, isolating the victim from the legitimate network.
> 2. **Identity enumeration**: The bootstrap node learns the AgentId,
>    public key, capabilities, and endpoints of all connecting agents.
> 3. **DHT poisoning**: The bootstrap node can inject false AgentRecords
>    into the DHT (though all records must be validly signed).
> 4. **Discovery disruption**: The bootstrap node can reject legitimate
>    announcements.
>
> Mitigations (normative):
> - Implementations MUST support configuring multiple bootstrap nodes.
> - Implementations SHOULD use at least 3 bootstrap nodes from different
>   administrative domains.
> - Implementations SHOULD use PEX (Section 5) with multiple peers to
>   cross-check bootstrap node responses.
> - Bootstrap nodes SHOULD rate-limit requests (Section 3.4).
>
> Limitations (v1):
> - No protocol-level mechanism to detect a malicious bootstrap node.
> - No mechanism to verify bootstrap node honesty.
> - Bootstrap nodes can enumerate all connecting agents (privacy concern,
>   see §8.5).

---

## A-T6: Strengthen UCAN Chain Depth Requirement

**Source**: REVIEW-0004 TH3
**Severity**: HIGH
**RFCs Affected**: RFC-0003 §8.5

### Amendment

Change RFC-0003 §8.5 from:

> Mitigation: implementations SHOULD enforce a maximum chain depth
> (RECOMMENDED: 8).

To:

> Implementations MUST enforce a maximum UCAN delegation chain depth
> of 8. Tokens that exceed this depth MUST be rejected with error code
> 3005 (DELEGATION_CHAIN_TOO_LONG).
>
> Implementations SHOULD use short UCAN expiry times (RECOMMENDED: 1 hour
> / 3600 seconds) to limit the blast radius of token theft.

Also add error code 3005 to RFC-0005 §3.4 if not already present.

---

## A-T7: Strengthen DoS Mitigation for Internet-Facing Deployments

**Source**: REVIEW-0004 TH5
**Severity**: HIGH
**RFCs Affected**: RFC-0002 §5.8, RFC-0004 §3.4

### Amendment

Change RFC-0002 §5.8 from:

> Deployments facing DoS threats (e.g., Internet-facing bootstrap nodes)
> MAY implement a pre-verification mechanism...

To:

> Deployments facing DoS threats (e.g., Internet-facing bootstrap nodes,
> public network deployments) SHOULD implement the pre-verification
> mechanism described in this section. Private network deployments or
> authenticated environments MAY omit it.
>
> The DoS mitigation profile provides cheap HMAC verification (~1μs)
> before expensive ML-DSA-65 signature verification (~1ms), reducing
> the cost of rejecting invalid ClientHello messages by ~1000x.

Add to RFC-0004 §3.4:

> Bootstrap nodes MUST limit lookup responses to 5 AgentRecords for
> unauthenticated requests (requests without a valid AgentRecord
> signature). Authenticated requests MAY receive up to 10 records.
>
> Implementations SHOULD enforce a maximum number of concurrent streams
> per connection (RECOMMENDED: 100) to prevent resource exhaustion.

---

## A-T8: Add Security Limitations Section

**Source**: REVIEW-0004 TM6
**Severity**: MEDIUM
**RFCs Affected**: RFC-0001 §9

### Amendment

Add a new subsection §9.6 to RFC-0001:

> ### 9.6 Security Limitations (v1)
>
> The following security properties are NOT provided by AAFP v1 and are
> explicitly out of scope:
>
> 1. **Network partition tolerance**: No mechanism for detecting or
>    handling network partitions. The v1 DHT is in-memory with no
>    replication or consistency guarantees.
> 2. **Traffic analysis resistance**: No padding or obfuscation
>    mechanism. AAFP traffic is identifiable by characteristic
>    handshake sizes (ML-DSA-65 keys and signatures are large).
> 3. **Identity hiding**: AgentId is sent to the peer in ClientHello
>    and is public in the DHT. No ephemeral identity mechanism.
> 4. **Anonymous bootstrap**: No mechanism for anonymous bootstrap.
>    Bootstrap nodes learn the identity of all connecting agents.
> 5. **Application-layer encryption**: No encryption beyond TLS.
>    If TLS confidentiality is broken, all application data is exposed.
> 6. **Session resumption**: Deferred to a future RFC.
> 7. **NAT traversal**: Deferred to a future RFC.
> 8. **Revocation**: No in-protocol revocation mechanism (see RFC-0003
>    §8.4).
> 9. **Key rotation**: No in-protocol key rotation mechanism (see
>    RFC-0003 §2.5).
> 10. **Sybil resistance**: No proof-of-work, reputation system, or
>     trusted issuer requirements (see RFC-0004 §8.3).
>
> These limitations are documented to set explicit expectations. Future
> RFCs may address some or all of these. Implementations and deployments
> MUST assess whether these limitations are acceptable for their threat
> model.

---

## A-T9: Document Forward Secrecy Properties

**Source**: REVIEW-0004 TH7
**Severity**: HIGH
**RFCs Affected**: RFC-0003 §8

### Amendment

Add to RFC-0003 §8.1 (Identity Binding):

> #### Forward Secrecy Properties
>
> - **Transport-layer traffic**: Forward secrecy is provided by TLS 1.3
>   with X25519MLKEM768. If TLS session keys are compromised in the
>   future, past transport-layer traffic remains confidential.
> - **Application-layer identity**: NO forward secrecy. AgentRecords and
>   UCAN tokens are self-signed with ML-DSA-65. If the secret key is
>   compromised, the attacker can forge records and tokens with arbitrary
>   past timestamps (subject to `expires_at` validation).
> - **Session metadata**: Forward secrecy depends on TLS. If TLS session
>   keys are compromised, session metadata (Session ID, capabilities)
>   can be derived from recorded handshake messages.
>
> The lack of forward secrecy for application-layer identity is a known
> limitation. Short AgentRecord expiry times (30 days max, see §8.4)
> limit the window of vulnerability.

---

## Amendment Summary

| ID | Source | Severity | RFCs | Type |
|----|--------|----------|------|------|
| A-C1 | R3-C1,C4 | CRITICAL | 0002 §5.6,§5.7 | Interop fix |
| A-C2 | R3-C2 | CRITICAL | 0002 §5.6,§8.1 | Interop fix |
| A-C3 | R3-C3 | CRITICAL | 0002 §6.4 | Interop fix |
| A-H1 | R3-H1 | HIGH | 0002 §6.1 | Clarification |
| A-H2 | R3-H2 | HIGH | 0002 §6.4 | Clarification |
| A-H3 | R3-H3 | HIGH | 0003 §3.5 | Clarification |
| A-H4 | R3-H4 | HIGH | 0002 §8.1 | Clarification |
| A-H5 | R3-H5 | HIGH | 0002 §5.2,§7.1 | Clarification |
| A-H6 | R3-H6 | HIGH | 0002 §5.6 | Subsumed by A-C1 |
| A-M1 | Analysis | HIGH | 0002 §5.7 | Interop fix |
| A-M2 | R3-M4 | MEDIUM | 0002 §8.1, 0003 §4.5 | Clarification |
| A-M3 | R3-M9 | MEDIUM | 0002 §5.8 | Clarification |
| A-T1 | R4-TH1 | HIGH | 0001 §9 | Normative gap |
| A-T2 | R4-TH4 | HIGH | 0003 §2.6 | Normative gap |
| A-T3 | R4-TC1 | CRITICAL | 0003 §8.4 | Normative gap |
| A-T4 | R4-TC2,TH8 | CRITICAL | 0003 §8 | Normative gap |
| A-T5 | R4-TH2 | HIGH | 0004 §3.1,§8.4 | Normative gap |
| A-T6 | R4-TH3 | HIGH | 0003 §8.5 | Normative gap |
| A-T7 | R4-TH5 | HIGH | 0002 §5.8, 0004 §3.4 | Normative gap |
| A-T8 | R4-TM6 | MEDIUM | 0001 §9 | Documentation |
| A-T9 | R4-TH7 | HIGH | 0003 §8.1 | Documentation |

**Total**: 21 amendments (4 CRITICAL, 12 HIGH, 4 MEDIUM, 1 subsumed)
