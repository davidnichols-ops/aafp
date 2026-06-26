# REVIEW-0003: Independent Specification Review (Cold-Read Implementer Perspective)

**Review Date**: 2025-06-25
**Reviewer**: Independent reviewer performing cold-read implementation simulation
**RFCs Reviewed**: RFC-0001 through RFC-0006 (Freeze Candidate Revision 2)
**Methodology**: Reviewer acted as an implementer who has never seen the codebase, attempting to implement each subsystem purely from the specification text. Each implementation question was answered with the reviewer's interpretation, then ambiguities were identified and rated by whether two independent readers would interpret the text differently.

## Methodology

The reviewer answered eight implementation questions:
1. "Implement the handshake"
2. "Implement the framing layer"
3. "How do extensions negotiate?"
4. "What exactly gets signed?"
5. "How is the transcript hash computed?"
6. "How is the Session ID derived?"
7. "What error codes exist and when are they used?"
8. "How does CBOR encoding work in AAFP?"

For each, the reviewer documented their interpretation, then identified ambiguities that would cause two independent implementers to produce non-interoperable code.

## Findings by Severity

### CRITICAL (Would cause non-interoperability)

| # | ID | Title | Location |
|---|----|-------|----------|
| 1 | C1 | Transcript hash vs signature input contradiction | RFC-0002 §5.6 |
| 2 | C2 | Canonical CBOR for excluded fields ambiguity | RFC-0002 §5.6 |
| 3 | C3 | Missing extension critical bit in handshake negotiation | RFC-0002 §6.4 |
| 4 | C4 | ServerHello signature input contradiction | RFC-0002 §5.6 |

### HIGH (Would likely cause bugs)

| # | ID | Title | Location |
|---|----|-------|----------|
| 5 | H1 | Ambiguous extension section ordering | RFC-0002 §3.2 vs §6.1 |
| 6 | H2 | Unclear extension data semantics in negotiation | RFC-0002 §6.4 |
| 7 | H3 | Missing domain separator length specification | RFC-0002 §5.6, RFC-0003 §3.5 |
| 8 | H4 | Ambiguous map key sorting for integer keys | RFC-0002 §8.1 |
| 9 | H5 | Missing stream 0 state after handshake | RFC-0002 §5.2, §4.7 |
| 10 | H6 | Unclear when to update transcript hash | RFC-0002 §5.6 |

### MEDIUM (Could cause confusion)

| # | ID | Title | Location |
|---|----|-------|----------|
| 11 | M1 | Unclear order of verification steps | RFC-0002 §5.3 |
| 12 | M2 | Unclear extension data length field size / byte order | RFC-0002 §6.1 |
| 13 | M3 | Missing minimum frame size | RFC-0002 §3.4 |
| 14 | M4 | Contradiction in key type rules (integer vs string) | RFC-0002 §8.1 vs RFC-0003 §4.5 |
| 15 | M5 | Error code range ambiguity (16-bit vs 4-digit) | RFC-0005 §2 |
| 16 | M6 | Missing error code for nonce reuse detection | RFC-0005 §3.3 vs RFC-0002 §5.9 |
| 17 | M7 | Unclear nonce concatenation order | RFC-0002 §5.7 |
| 18 | M8 | Missing HKDF parameter specification | RFC-0002 §5.7 |
| 19 | M9 | Missing transcript hash for DoS MAC | RFC-0002 §5.8 |
| 20 | M10 | Missing extension rejection mechanism | RFC-0002 §6.4 |
| 21 | M11 | Unclear relationship between handshake and frame extensions | RFC-0002 §6.4 |
| 22 | M12 | Unclear float encoding usage | RFC-0002 §8.1 |

### LOW (Minor)

| # | ID | Title | Location |
|---|----|-------|----------|
| 23 | L1 | Missing maximum handshake timeout | — |
| 24 | L2 | Unclear stream ID assignment for server-initiated streams | RFC-0002 §7.1 |
| 25 | L3 | Reserved field handling ambiguity | RFC-0002 §3.1 vs RFC-0006 §9.3 |
| 26 | L4 | Missing extension deactivation mechanism | — |
| 27 | L5 | Unclear if ExtensionEntry data is signed | RFC-0002 §5.6 |
| 28 | L6 | Missing specification for empty arrays | RFC-0002 §5.3-5.4 |
| 29 | L7 | No transcript hash reset on retries | — |
| 30 | L8 | No Session ID validation by client | RFC-0002 §5.7 |
| 31 | L9 | Missing Session ID uniqueness guarantees | RFC-0002 §5.7 |
| 32 | L10 | Inconsistent fatal error list | RFC-0005 §4.3-4.4 |
| 33 | L11 | Missing error code for TLS exporter unavailable | RFC-0002 §2.5 |
| 34 | L12 | No error code for extension parameter mismatch | — |
| 35 | L13 | Missing CBOR major type specifications | — |
| 36 | L14 | No CBOR decoder strictness specification | RFC-0002 §8.1 |

## Detailed Findings

### C1: Transcript hash vs signature input contradiction

**Location**: RFC-0002 §5.6

**Description**: The signature formulas in §5.6 do NOT use the transcript hash `h`. They use direct SHA-256 of concatenated values (e.g., `SHA-256(tls_binding || canonical_CBOR(ClientHello_without_sig_and_mac))`). But the text says "The transcript hash is used for ClientFinished signature" and step 3 says to update the transcript hash with `h = SHA-256(h || canonical_CBOR(...))`.

The signature formula hashes `tls_binding || CBOR`, but the transcript update hashes `h || CBOR` where `h = SHA-256(tls_binding)`. These produce different results. An implementer following the transcript hash description would compute signatures over different bytes than an implementer following the explicit formulas.

**Impact**: Implementers might use `h` for all signatures, which would be wrong per the formulas. Two implementations would produce non-matching signatures.

**Recommendation**: Reconcile the two descriptions. Either (a) signatures use the running transcript hash directly, or (b) signatures use explicit concatenation and the transcript hash is only for ClientFinished and Session ID derivation. Pick one model and use it consistently with explicit byte-level examples.

### C2: Canonical CBOR for excluded fields ambiguity

**Location**: RFC-0002 §5.6

**Description**: When computing `canonical_CBOR(ClientHello_without_signature_and_receiver_mac)`, it is unclear whether this means:
- (a) Encode the map with keys 1-6, 8, 10 (skipping keys 7 and 9)
- (b) Encode the full map then remove bytes for keys 7 and 9
- (c) Encode a new map with only the included fields

These produce different CBOR encodings (different map lengths, different byte layouts).

**Impact**: Different implementations could produce different CBOR encodings of the "same" logical structure, causing signature verification failures.

**Recommendation**: Specify explicitly that the signature input is a NEW canonical CBOR map containing ONLY the included fields (option a). Add a normative statement: "The signature input is the canonical CBOR encoding of a map containing exactly the fields listed in the signature input specification, with all other fields omitted."

### C3: Missing extension critical bit in handshake negotiation

**Location**: RFC-0002 §6.4

**Description**: The handshake `ExtensionEntry` structure (CBOR map with keys 1: type, 2: data) has no "critical" field, but frame extensions (§6.1) do have a critical bit. There is no way for a client to indicate that a proposed handshake extension is mandatory vs optional.

**Impact**: Server cannot distinguish mandatory from optional client proposals. The requirement "If client proposed mandatory extension and server didn't accept → ERROR 2005" cannot be implemented because the client cannot mark an extension as mandatory.

**Recommendation**: Add a `critical` field (boolean, key 3) to the handshake ExtensionEntry structure. Alternatively, define a separate "required extensions" list in ClientHello.

### C4: ServerHello signature input contradiction

**Location**: RFC-0002 §5.6

**Description**: The ServerHello signature formula is:
```
SHA-256(tls_binding || CH_CBOR || SH_CBOR_without_sig)
```
But the transcript hash computation (step 4) is:
```
h = SHA-256(h || canonical_CBOR(ServerHello_without_signature))
```
where `h = SHA-256(tls_binding || CH_CBOR)` from step 3.

So the signature hashes `tls_binding || CH || SH`, but the transcript hashes `SHA-256(tls_binding || CH) || SH`. These are different.

**Impact**: ServerHello signature verification would fail if using the transcript hash instead of the explicit concatenation.

**Recommendation**: Same as C1 — pick one model and use it consistently.

### H1: Ambiguous extension section ordering

**Location**: RFC-0002 §3.2 vs §6.1

**Description**: §3.2 shows Extensions before Payload in the frame body, but §6.1 describes extension encoding without clarifying if multiple extensions are concatenated or have additional framing.

**Recommendation**: Specify that multiple extensions are concatenated directly (each extension is self-delimiting via its Data Length field) within the Extensions section.

### H2: Unclear extension data semantics in negotiation

**Location**: RFC-0002 §6.4

**Description**: §6.4 says "server MAY include extension data that differs from the client's proposal" but doesn't specify what this means or give examples.

**Recommendation**: Add an example of parameter negotiation (e.g., max frame size: client proposes 1 MiB, server selects 256 KiB).

### H3: Missing domain separator length specification

**Location**: RFC-0002 §5.6, RFC-0003 §3.5

**Description**: The domain separator is described as "a UTF-8 string, NOT length-prefixed" but the signature input `"aafp-v1-handshake" || hash` doesn't clarify if this is raw byte concatenation of UTF-8 bytes.

**Recommendation**: Specify explicitly: "The domain separator is encoded as its raw UTF-8 bytes (no null terminator, no length prefix) and concatenated directly with the message bytes."

### H4: Ambiguous map key sorting for integer keys

**Location**: RFC-0002 §8.1

**Description**: §8.1 says "Map keys are sorted by length-first canonical byte ordering" but all AAFP maps use integer keys. For integers 1-23, CBOR encodes them as single bytes. For integers 24-255, CBOR encodes them as two bytes. The sort order between a single-byte key 23 and a two-byte key 24 needs clarification.

**Recommendation**: Clarify that integer keys are sorted by their CBOR encoding's byte ordering (which is what RFC 8949 §4.2.3 specifies for length-first deterministic encoding). Add an explicit example.

### H5: Missing stream 0 state after handshake

**Location**: RFC-0002 §5.2, §4.7

**Description**: The specification doesn't say whether stream 0 remains open or should be closed after the handshake completes. §4.7 says PING frames MAY be sent on stream 0.

**Recommendation**: Specify that stream 0 remains open for the lifetime of the connection and is used for connection-level frames (PING/PONG, GOAWAY, ERROR with fatal severity).

### H6: Unclear when to update transcript hash

**Location**: RFC-0002 §5.6 step 3

**Description**: Step 3 says "After sending or receiving ClientHello, update" but doesn't specify if this happens before or after signature computation.

**Recommendation**: Specify the exact ordering: (1) compute signature, (2) send message, (3) update transcript hash. Or: (1) receive message, (2) update transcript hash, (3) verify signature. Make this explicit.

## Recommendations

1. **Resolve C1/C4 immediately**: Pick one signature model (transcript hash OR explicit concatenation) and use it consistently. Add byte-level test vectors.
2. **Resolve C2**: Specify that signature input is a new CBOR map with only included fields.
3. **Resolve C3**: Add critical bit to handshake ExtensionEntry.
4. **Resolve H1-H6**: Add clarifying text and examples.
5. **Create normative test vectors**: Add a test vector appendix to RFC-0002 with known-good signature computations.
6. **Resolve MEDIUM findings**: Address in the same amendment batch.
