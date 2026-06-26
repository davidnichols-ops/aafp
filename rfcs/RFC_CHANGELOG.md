# AAFP RFC Changelog

```
Document:         RFC_CHANGELOG.md
Date:             2025-06-25
Status:           Current
Scope:            Records all changes to AAFP RFCs from initial draft
                  (Revision 1) through the current revision (Revision 2).
```

---

## Revision 2 (2025-06-25)

Revision 2 applies all approved amendments from AMENDMENTS-0001,
following the approval gate process documented in AMENDMENT_STATUS.md.

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
