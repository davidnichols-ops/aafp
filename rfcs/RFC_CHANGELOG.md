# AAFP RFC Changelog

```
Document:         RFC_CHANGELOG.md
Date:             2025-01-16
Status:           Current
Scope:            Records all changes to AAFP RFCs from initial draft
                  (Revision 1) through the current revision (Revision 5).
```

---

## Revision 5 (2025-01-16) — Freeze Candidate (Clarification)

Revision 5 applies one specification clarification (SA-0003) discovered
during implementation review of the AgentRecord 30-day expiry rule.
This is a clarification-only change with no wire format impact, no new
error codes, and no modification to the §3.6 verification procedure.

Per the freeze commitment (RFC-0006 §2.5), clarifications of ambiguous
normative text discovered during implementation justify a revision
under the freeze candidate stage.

### Clarification Applied

**SA-0003: AgentRecord 30-day expiry — warning vs. rejection**

- **Issue**: RFC-0003 §8.4 stated "Implementations MUST support
  AgentRecord expiry no longer than 30 days" and "MUST warn users if
  expires_at exceeds 30 days from the current time." This was
  misreadable as a verification-rejection requirement. However, the
  normative verification procedure in §3.6 contains no 30-day rejection
  step (only past-expiry rejection at step 6), no error code exists for
  "expiry too long," and the originating review (REVIEW-0004 TC1) and
  amendment (AMENDMENTS-0002 A-T3) both specified "warn users," not
  "reject." Additionally, the existing implementation helper
  `exceeds_max_expiry()` used `expires_at - created_at` (total lifetime)
  while §8.4 specifies `expires_at - current_time`.
- **Resolution**: RFC-0003 §8.4 point 1 clarified that the 30-day limit
  is a deployment mitigation, not a verification requirement. The
  verification procedure in §3.6 does NOT reject records whose lifetime
  exceeds 30 days. The warning predicate is `expires_at - current_time >
  2,592,000`, computed from the current time, not from `created_at`.
- **Wire format impact**: None. No new error codes, no §3.6 change, no
  protocol registry change.
- **Implementation impact**: The Rust `exceeds_max_expiry()` helper
  (using `created_at`) was replaced with `exceeds_max_expiry_warning(now)`
  (using `now`, matching §8.4). `verify()` is unchanged. The Go
  implementation added `ExceedsMaxExpiryWarning(now)` with the same
  predicate. Both implementations added conformance tests R5-001
  through R5-004 verifying that `verify()` accepts >30-day unexpired
  records and that the warning predicate fires correctly.

### RFC-0001 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 5 (no content changes) | — |

### RFC-0002 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 5 (no content changes) | — |

### RFC-0003 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 5 | — |
| 8.4 | Added clarification paragraph to point 1: 30-day limit is a deployment warning, not a verification rejection; predicate uses current_time, not created_at | SA-0003 |

### RFC-0004 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 5 (no content changes) | — |

### RFC-0005 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 5 (no content changes) | — |

### RFC-0006 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 5 (no content changes) | — |

---

## Revision 4 (2025-01-15) — Freeze Candidate (Post-Interop)

Revision 4 applies two specification clarifications discovered during
bidirectional interoperability testing between the Rust reference
implementation and the Go independent implementation (see
INTEROP-0001.md). Both clarifications are narrow edge cases that do
not change the wire format — they clarify existing normative text
that was ambiguous enough to cause divergent implementation behavior.

No amendments were processed through the AMENDMENTS-0001/0002
process. These clarifications are justified under the freeze
commitment (RFC-0006 §2.5) as interoperability issues discovered
during implementation.

### Clarifications Applied

**SA-0001: CapabilityDescriptor metadata field presence**

- **Issue**: RFC-0003 §4.4 stated metadata (key 2) is "optional, may
  be absent or empty" but did not specify whether the field must be
  present on the wire when empty, or how an empty map should be
  encoded. The Rust reference always includes key 2 as an empty map;
  the Go independent implementation initially omitted it. This caused
  signature verification failures because the canonical CBOR inputs
  differed.
- **Resolution**: RFC-0003 §4.4 clarified that key 2 MUST always be
  present. An empty metadata map MUST be encoded as `a0` (empty CBOR
  map), not omitted. This ensures deterministic encoding.
- **Wire format impact**: None for implementations that already
  include key 2. Implementations that omitted key 2 must now include
  it as an empty map.

**SA-0002: Empty CBOR map key-type ambiguity**

- **Issue**: CBOR encodes empty maps as `a0` (major type 5, 0
  entries), which is the same encoding for both int-keyed and
  string-keyed empty maps. Decoders that check the CBOR major type
  to determine key type will see major type 5 (int-keyed) for an
  empty string-keyed map, causing rejection of valid data.
- **Resolution**: RFC-0002 §8.1 clarified that for AAFP fields with
  a schema-defined key type, the key type MUST be determined from
  the enclosing schema, not from the CBOR major type. This applies
  to all `map<tstr, T>` and `map<uint, T>` fields.
- **Wire format impact**: None. This is a decoder behavior
  clarification only.

### RFC-0001 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 4 (no content changes) | — |

### RFC-0002 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 4 | — |
| 8.1 | Added empty map key-type interpretation rule | SA-0002 |

### RFC-0003 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 4 | — |
| 4.2 | Updated schema comment: metadata "MUST be present, MAY be empty" | SA-0001 |
| 4.4 | Changed metadata from "No" to "Yes" (required); added Revision 4 clarification paragraph | SA-0001 |
| 4.5 | Added empty map key-type clarification paragraph | SA-0002 |

### RFC-0004 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 4 (no content changes) | — |

### RFC-0005 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 4 (no content changes) | — |

### RFC-0006 Changes

| Section | Change | Clarification |
|---------|--------|---------------|
| Header | Updated to Revision 4 (no content changes) | — |

---

## Revision 3 (2025-06-25) — Freeze Candidate (Post-Review)

Revision 3 applies amendments from AMENDMENTS-0002, addressing findings
from two independent reviews:

- **REVIEW-0003**: Cold-read implementer review (found 4 CRITICAL
  interoperability bugs, 6 HIGH issues)
- **REVIEW-0004**: Formal threat model review (found 2 CRITICAL, 8 HIGH
  normative gaps)

Per the freeze commitment (RFC-0006 Section 2.5), interoperability and
security issues discovered during freeze justify normative fixes.

### Amendments Applied

21 amendments from AMENDMENTS-0002:
- 4 CRITICAL interoperability fixes (A-C1, A-C2, A-C3, A-M1)
- 6 HIGH clarifications (A-H1 through A-H5, A-H6 subsumed by A-C1)
- 3 MEDIUM clarifications (A-M2, A-M3, plus A-H6 subsumed)
- 9 normative gap closures from threat model (A-T1 through A-T9)

### Key Changes

**Critical interoperability fixes (RFC-0002)**:
1. **A-C1**: Unified signature and transcript hash model. All signatures
   now sign over the running transcript hash AFTER the current message
   is folded in (TLS 1.3 model). Removed contradictory concatenation
   formulas.
2. **A-C2**: Defined canonical CBOR for signature inputs as a NEW map
   with only included fields (excluded fields omitted entirely).
3. **A-C3**: Added `critical` field (key 3, bool) to handshake
   ExtensionEntry to distinguish mandatory from optional extensions.
4. **A-M1**: Fixed session ID circular dependency. Session ID now
   derived from transcript hash after ClientHello (not after ServerHello,
   which contains session_id).

**Threat model normative gaps**:
5. **A-T1**: Added Trust Model section to RFC-0001 (§9.0).
6. **A-T2**: Changed fingerprint display from SHOULD to MUST.
7. **A-T3**: Strengthened key compromise documentation with blast radius.
8. **A-T4**: Added Key Management Requirements section (§8.6) to RFC-0003.
9. **A-T5**: Added bootstrap node compromise scenario and multi-node
   requirement (MUST support, SHOULD use 3+).
10. **A-T6**: Changed UCAN chain depth from SHOULD to MUST (max 8).
11. **A-T7**: Changed DoS pre-verification from MAY to SHOULD for
    Internet-facing deployments.
12. **A-T8**: Added Security Limitations section to RFC-0001 (§9.6).
13. **A-T9**: Documented forward secrecy properties in RFC-0003.

### RFC-0001 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Updated to Revision 3 | — |
| 9.0 | NEW: Trust Model section | A-T1 |
| 9.6 | NEW: Security Limitations (v1) section | A-T8 |

### RFC-0002 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Updated to Revision 3 | — |
| 5.2 | Added stream 0 lifecycle (remains open, connection-level frames) | A-H5 |
| 5.6 | Rewritten: unified transcript hash + signature model, signature input encoding rules | A-C1, A-C2 |
| 5.7 | Fixed session ID derivation (uses h_after_clienthello, not final h); added client verification requirement | A-M1 |
| 5.8 | Changed MAY to SHOULD for Internet-facing; clarified DoS MAC input matches CH_CBOR | A-T7, A-M3 |
| 6.1 | Clarified extension concatenation and big-endian data length | A-H1 |
| 6.4 | Added critical field (key 3) to ExtensionEntry; added parameter negotiation section; updated negotiation rule 4 | A-C3, A-H2 |
| 8.1 | Clarified integer key sorting with examples; added metadata map exception; clarified float rule | A-H4, A-M2 |
| 8.4 | Added ExtensionEntry key 3 (critical) to mapping table | A-C3 |

### RFC-0003 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Updated to Revision 3 | — |
| 2.6 | Changed fingerprint display from SHOULD to MUST; added rationale | A-T2 |
| 3.5 | Clarified domain separator encoding (raw UTF-8 bytes, no null terminator, with byte example) | A-H3 |
| 8.4 | Rewritten: added blast radius (7 items), compromise response, MUST for 30-day max expiry | A-T3 |
| 8.5 | Changed UCAN chain depth from SHOULD to MUST (max 8); added short expiry recommendation | A-T6 |
| 8.6 | NEW: Key Management Requirements (generation, storage, rotation, compromise detection, forward secrecy) | A-T4, A-T9 |

### RFC-0004 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Updated to Revision 3 | — |
| 3.1 | Added MUST for multiple bootstrap nodes, SHOULD for 3+ from different domains | A-T5 |
| 3.4 | Added MUST for lookup limit (5 unauthenticated), SHOULD for max concurrent streams | A-T7 |
| 8.4 | Added Bootstrap Node Compromise subsection with 4 attack scenarios and normative mitigations | A-T5 |

### RFC-0005 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Updated to Revision 3 (no content changes) | — |

### RFC-0006 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Updated to Revision 3 (no content changes) | — |

---

## Revision 2 (2025-06-25) — Freeze Candidate

Revision 2 applies all approved amendments from AMENDMENTS-0001,
following the approval gate process documented in AMENDMENT_STATUS.md.

**Specification status changed from Draft to Freeze Candidate.**

The RFCs are designated as Candidate Protocol 0.9. No further
architectural changes will be made unless an interoperability or
security issue is discovered. See RFC-0006 Section 2.5 for the
specification lifecycle and freeze commitment.

Governance sections added to RFC-0006 (Section 11):
- RFC lifecycle (Draft → Freeze Candidate → Proposed → Stable)
- Amendment process (proposal → approval gate → application → revision)
- Security disclosure process
- Compatibility policy
- Conformance test suite (future)

### Amendments Applied

18 amendments were reviewed through the approval gate. 16 were
accepted (13 as-is, 3 with modifications), 2 were resolved by other
amendments. 0 were rejected or deferred.

### Cryptographic Verification

All cryptographic choices were verified against:
- FIPS 204 (final, August 2024) — ML-DSA signing mode
- RFC 8446 (TLS 1.3) — exporter API, transcript hash
- RFC 9266 (Channel Bindings for TLS 1.3) — tls-exporter label
- RFC 8949 (CBOR) — deterministic encoding (obsoletes RFC 7049)
- IETF CFRG guidance — domain separation (prefix-free sets)

Three modifications were made during crypto verification:
1. C5: TLS exporter label changed from "aafp-channel-binding" to
   "EXPORTER-AAFP-Channel-Binding" (RFC 9266 naming convention)
2. H2: DoS MAC security property clarified (proves sender knows
   receiver AgentId, not sender authentication)
3. H4: expires_at trust model clarified (self-attested; AgentRecord
   authoritative when available; use earlier expiry)

Two additional changes from crypto verification:
4. ML-DSA-65 signing mode recommendation added (FIPS 204 hedged
   signing as default)
5. RFC 7049 references updated to RFC 8949

### RFC-0001 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Added "Revised" line | — |
| 7.3 | Replaced v0.1 conformance with reference to RFC-0006 §8.1 | C6 |
| 9.3 | Updated identity binding to describe TLS channel binding | C5 |
| 9.5 | Added TLS channel binding and AgentId fingerprints to TOFU mitigations | C5, H11 |

### RFC-0002 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Added "Revised" line | — |
| 2.5 | Added TLS channel binding computation step and exporter label | C5 |
| 3.4 | FRAME_TOO_LARGE made non-fatal by default | H5 |
| 4.3 | RpcRequest: integer keys, params changed from bstr to any | C1, C4 |
| 4.4 | RpcResponse: integer keys, result changed from bstr to any | C1, C4 |
| 4.5 | CloseMessage: integer keys | C1 |
| 4.6 | ErrorMessage: integer keys | C1 |
| 4.7 | PING: clarified stream semantics (any open stream, stream 0 recommended) | H6 |
| 4.8 | PONG: clarified same-stream requirement | H6 |
| 5.3 | ClientHello: integer keys, added expires_at (8), receiver_mac (9), key_algorithm (10) | C1, C3, H2, H4, H8 |
| 5.4 | ServerHello: integer keys, added expires_at (9), key_algorithm (10) | C1, C3, H4, H8 |
| 5.5 | ClientFinished: integer keys | C1 |
| 5.6 | NEW: Transcript Hash (running SHA-256 with TLS channel binding and domain separator) | C2, C5, H1 |
| 5.7 | Session ID: normative HKDF derivation (was implementation-defined) | C2 |
| 5.8 | NEW: DoS Mitigation Profile (optional, HMAC pre-verification) | H2 |
| 5.9 | Handshake error handling: added error codes 2006, 2007, 2009 | C5, H2, H3 |
| 6.3 | Updated to reference new Section 6.4 | C3 |
| 6.4 | NEW: Handshake Extension Negotiation (ExtensionEntry format, negotiation rules) | C3 |
| 8.1 | Updated CBOR reference from RFC 7049 to RFC 8949 | Crypto verification |
| 8.4 | NEW: Integer Key Mapping Table | C1 |
| 11 | Updated references (RFC 8949, RFC 9266, cross-RFC refs) | — |

### RFC-0003 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Added "Revised" line | — |
| 2.1 | AgentId: fixed error code (2007 not 2001), added algorithm independence note | H3, H8 |
| 2.2 | Renamed from "AgentId Encoding" to "AgentId Encoding and Hash Agility"; added hash agility future consideration | User guidance |
| 2.3 | NEW: Key Algorithm Registry (ML-DSA-65, ML-DSA-44, ML-DSA-87, SLH-DSA-128s) | H8 |
| 2.4 | Renumbered (was 2.3); added signing mode recommendation (FIPS 204 hedged) | Crypto verification |
| 2.5 | Renumbered (was 2.4) | — |
| 2.6 | NEW: AgentId Fingerprint format (base32 + CRC32) | H11 |
| 3.2 | AgentRecord: added field 9 (key_algorithm) | H8 |
| 3.3 | Field semantics: updated for key_algorithm field | H8 |
| 3.4 | Signature computation: added domain separator "aafp-v1-record" | H1 |
| 3.5 | NEW: Domain Separation (prefix-free set, three separators defined) | H1 |
| 3.6 | Verification: updated for domain separator, key_algorithm check, error codes | H1, H3, H8 |
| 3.7 | Forward compatibility: updated reserved key range (≥10) | H8 |
| 5.4 | UCAN token: added domain separator "aafp-v1-ucan" to signature | H1 |
| 6.3 | Session ID: normative HKDF derivation (was implementation-defined) | C2 |
| 7.1 | Handshake flow diagram: added channel binding, expires_at, key_algorithm, domain separators | C5, H1, H4, H8 |
| 7.2 | Verification steps: added expires_at, key_algorithm, DoS MAC, error codes, trust model | H2, H3, H4, H8 |
| 7.3 | Updated extension reference to Section 6.4 | C3 |
| 8.1 | Identity binding: updated to describe TLS channel binding with RFC 9266 | C5 |
| 8.3 | MITM: added channel binding and fingerprint mitigations | C5, H11 |
| 8.4 | Key compromise: expanded with revocation limitation, mitigations, future mechanism | H10 |
| 9 | IANA: added Key Algorithm Registry, Domain Separators, updated field key ranges | H8, H1 |
| 10 | References: updated (RFC 8949, RFC 8446, RFC 9266, RFC 4648, FIPS 205, cross-RFC) | — |

### RFC-0004 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Added "Revised" line | — |
| 3.3 | RPC methods: integer keys, params as CBOR any type | C4 |
| 3.4 | Bootstrap requirements: rate limiting, AgentRecord verification, 100K record limit | H12 |
| 6.2 | PEX method: integer keys | C4 |

### RFC-0005 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Added "Revised" line | — |
| 3.3 | Added error codes 2009 (RECEIVER_MAC_INVALID) and 2010 (UNSUPPORTED_ALGORITHM); updated descriptions | H2, H3, H8 |
| 4.4 | Removed 8001 from always-fatal list; made FRAME_TOO_LARGE non-fatal by default | H5 |
| 7 | Close code table: added 2007 (INVALID_AGENT_ID) | H3 |

### RFC-0006 Changes

| Section | Change | Amendment |
|---------|--------|-----------|
| Header | Added "Revised" line | — |
| 8.1 | Conformance requirements: expanded from 12 to 19 items (added channel binding, domain separators, key_algorithm, expires_at, integer keys, session ID derivation, extension negotiation) | C1-C6, H1, H4, H8 |
| 10 | IANA: added Key Algorithm Registry, Domain Separators, Handshake Extension Types | H8, H1, C3 |

---

## Revision 1 (2025-06-25, Initial Draft)

Initial publication of RFC-0001 through RFC-0006.

### Known Issues (Addressed in Revision 2)

- CBOR map key type inconsistency (string vs integer keys)
- Undefined handshake transcript construction
- Undefined handshake extension format
- RPC params/result encoding ambiguity
- No TLS channel binding (relay attack vulnerability)
- Stale v0.1 conformance section
- No domain separation in signatures
- No DoS pre-verification mechanism
- Error code misuse (2001 vs 2007)
- Missing expires_at in handshake
- FRAME_TOO_LARGE fatal/stream contradiction
- PING/PONG stream semantics ambiguity
- No signature algorithm agility
- No revocation mechanism documentation
- No fingerprint format for TOFU verification
- Bootstrap discovery amplification risk

---

## Document Conventions

- "Revision N" refers to the document revision, not the protocol
  version. The protocol version remains 1 throughout.
- Changes are grouped by RFC, then by section.
- Each change references the amendment ID from AMENDMENTS-0001.
- Cryptographic verification changes are marked as "Crypto
  verification" rather than an amendment ID.
