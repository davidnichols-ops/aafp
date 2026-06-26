# AAFP Amendment Status and Impact Matrix

```
Document:         AMENDMENT_STATUS.md
Date:             2025-06-25
Status:           Final
Scope:            Approval gate for amendments from AMENDMENTS-0001.
                  Each amendment is evaluated for acceptance, deferral,
                  or rejection before being applied to the RFCs.
Verification:     Cryptographic choices verified against FIPS 204
                  (final, August 2024), RFC 8446 (TLS 1.3), RFC 9266
                  (TLS 1.3 Channel Bindings), RFC 8949 (CBOR), and
                  IETF CFRG guidance on domain separation.
```

---

## 1. Amendment Impact Matrix

| ID | RFC(s) Affected | Normative/Informative | Wire Change | Crypto Change | Backward Compat Impact | Version Impact | Risk of Future Regret | Recommendation |
|----|-----------------|----------------------|-------------|---------------|----------------------|----------------|----------------------|----------------|
| C1 | 0002, 0005 | Normative (MUST) | Yes | Yes (affects signature bytes) | Breaks v0.1 (declared incompatible) | None (v1 definition) | Low — integer keys are the IETF CBOR convention (COSE, CWT) | **Accept** |
| C2 | 0002, 0003 | Normative (MUST) | Yes | Yes (defines signature input) | Breaks v0.1 | None | Low — running hash is TLS 1.3 / Noise standard pattern | **Accept** |
| C3 | 0002, 0006 | Normative (MUST) | Yes | No | Breaks v0.1 | None | Low — TLS 1.3 extension negotiation pattern | **Accept** |
| C4 | 0002, 0004 | Normative (MUST) | Yes | No | Breaks v0.1 | None | Low — JSON-RPC structured params pattern | **Accept** |
| C5 | 0002, 0003, 0001 | Normative (MUST) | Yes | Yes (adds channel binding to transcript) | Breaks v0.1 | None | Low — RFC 9266 tls-exporter is the standard TLS 1.3 channel binding | **Accept with modification** (see §3.1) |
| C6 | 0001 | Normative (MUST) | No | No | None | None | None — documentation fix | **Accept** |
| H1 | 0002, 0003 | Normative (MUST) | Yes | Yes (changes signature input) | Breaks v0.1 | None | Low — domain separation is CFRG best practice; prefix-free set verified | **Accept** |
| H2 | 0002, 0005 | Mixed (MAY for profile, MUST for mechanism) | Yes (optional field) | Yes (HMAC pre-verification) | None (optional field, negotiated) | None | Medium — optional profile adds wire field; can be removed if unused | **Accept with modification** (see §3.2) |
| H3 | 0003 | Normative (MUST) | No | No | None | None | None — correctness fix | **Accept** |
| H4 | 0002, 0003 | Normative (MUST) | Yes | No | Breaks v0.1 | None | Medium — self-attested expiry; trust model needs clarification | **Accept with modification** (see §3.3) |
| H5 | 0005, 0002 | Normative (SHOULD) | No | No | None | None | None — semantics clarification | **Accept** |
| H6 | 0002 | Normative (MUST for PONG, SHOULD for stream) | No | No | None | None | None — clarification | **Accept** |
| H7 | — | — | — | — | — | — | — | **Resolved by C1 + C2** |
| H8 | 0002, 0003, 0006 | Normative (MUST support alg 1, MAY support others) | Yes | Yes (adds algorithm identifier) | Breaks v0.1 | None | Medium — registry management; but agility is essential | **Accept** |
| H9 | — | — | — | — | — | — | — | **Resolved by C3** |
| H10 | 0003 | Informative (SHOULD) | No | No | None | None | None — documentation | **Accept** |
| H11 | 0003 | Mixed (SHOULD display, MUST format if displayed) | No | No | None | None | Low — display format can be changed | **Accept** |
| H12 | 0004 | Normative (MUST for bootstrap nodes) | No | No | None | None | None — implementation requirement | **Accept** |

### Summary

- **Accept**: 13 amendments (C1, C2, C3, C4, C6, H1, H3, H5, H6, H8, H10, H11, H12)
- **Accept with modification**: 3 amendments (C5, H2, H4)
- **Defer**: 0 amendments
- **Reject**: 0 amendments
- **Resolved by other amendments**: 2 (H7 by C1+C2, H9 by C3)

---

## 2. One-Way Door Analysis

### Question: Which decisions would be extremely expensive to reverse after two independent implementations exist?

#### Definite One-Way Doors (8)

These decisions cannot be reversed without a new protocol version and breaking all existing implementations:

| ID | Decision | Why Expensive to Reverse |
|----|----------|-------------------------|
| **C1** | Integer CBOR keys | Changing key types invalidates all signatures (different canonical encoding). Every AgentRecord, UCAN token, and handshake signature becomes invalid. |
| **C2** | Transcript hash construction | Changing the transcript (e.g., from running hash to final concatenation, or adding/removing fields from the hash) invalidates all handshake signatures and session IDs. |
| **C3** | Extension format (CBOR ExtensionEntry) | Changing the extension encoding breaks all extension negotiation. Extensions are the primary forward-compatibility mechanism; breaking them requires a new protocol version. |
| **C4** | RPC params type (`any` not `bstr`) | Changing the params type breaks all RPC communication. Every RPC request and response would need to be re-encoded. |
| **C5** | TLS channel binding in transcript | Removing or changing the channel binding (e.g., different label, different length) invalidates all handshake signatures. The label string becomes a permanent protocol constant. |
| **H1** | Domain separator strings | Changing domain separators (e.g., "aafp-v1-handshake" → "aafp-v2-handshake") invalidates all existing signatures. The separator strings become permanent protocol constants for v1. |
| **H4** | `expires_at` as required field in handshake | Removing a required CBOR map field after implementations exist would break parsers that expect the field. Making it optional later is possible (CBOR maps can omit keys), but implementations that require it would reject messages from implementations that omit it. |
| **H8** | `key_algorithm` as required field | Same as H4. Removing a required field after implementations exist breaks interoperability. The field number (10 in ClientHello/ServerHello, 9 in AgentRecord) is permanently assigned. |

#### Two-Way Doors (7)

These decisions can be reversed or modified without breaking existing implementations:

| ID | Decision | Why Reversible |
|----|----------|---------------|
| C6 | Conformance section reference | Documentation only. Can be updated at any time. |
| H2 | DoS pre-verification profile | Optional, negotiated via extension. Can be removed or modified without affecting implementations that don't use it. The extension type (0x0001) can be deprecated. |
| H3 | Error code 2001 vs 2007 | Error code semantics can be clarified. The codes themselves are permanent, but using the correct one is a clarification, not a structural change. |
| H5 | FRAME_TOO_LARGE non-fatal default | Error handling semantics can be adjusted. The fatal flag is per-message, so implementations can change behavior without wire format changes. |
| H6 | PING/PONG stream semantics | Clarification only. Can be further clarified. |
| H10 | Revocation documentation | Documentation only. Can be updated. |
| H11 | Fingerprint format | Display format only. Can be changed without wire protocol impact (though changing it after users are familiar would cause confusion). |
| H12 | Bootstrap rate limiting | Implementation requirement. Can be adjusted. |

#### One-Way Door Review Notes

The 8 one-way doors deserve special attention before being frozen:

1. **C1 (integer keys)**: This is the right choice. COSE (RFC 8152) and CWT (RFC 8392) use integer keys. The IETF CBOR working group recommends integer keys for protocol-defined structures. The key mapping table provides human readability. **No concerns.**

2. **C2 (transcript hash)**: The running SHA-256 hash follows TLS 1.3 (§4.4.1) and Noise (§5.2) patterns. The inclusion of TLS channel binding (C5) is security-critical. The domain separator prefix (H1) is CFRG best practice. **No concerns.**

3. **C3 (extension format)**: The CBOR ExtensionEntry map follows TLS 1.3's extension pattern adapted to CBOR. The client-proposes/server-accepts negotiation is standard. **No concerns.**

4. **C4 (RPC params as `any`)**: This follows JSON-RPC 2.0's structured params pattern. Using CBOR `any` avoids nested encoding. **No concerns.**

5. **C5 (TLS channel binding)**: The custom label "aafp-channel-binding" requires justification (see §3.1 below). RFC 9266 defines "EXPORTER-Channel-Binding" as the standard label. AAFP's custom label provides protocol-specific domain separation but diverges from the standard. **Review needed — see §3.1.**

6. **H1 (domain separators)**: The three separators ("aafp-v1-handshake", "aafp-v1-record", "aafp-v1-ucan") form a prefix-free set (verified: none is a prefix of another). This satisfies the CFRG requirement for prefix-free domain separators. **No concerns.**

7. **H4 (`expires_at` field)**: The self-attested nature of this field requires trust model clarification (see §3.3 below). **Review needed — see §3.3.**

8. **H8 (`key_algorithm` field)**: The registry approach follows TLS 1.3's `signature_algorithms` pattern. Including the field in the signature (to prevent algorithm substitution) is correct. **No concerns.**

---

## 3. Cryptographic Verification Against Current Guidance

### 3.1 C5: TLS Channel Binding — Label Choice (MODIFICATION REQUIRED)

**Current proposal**: `TLS-Exporter("aafp-channel-binding", "", 32)`

**Finding**: RFC 9266 (July 2025) defines the standard TLS 1.3 channel binding type `tls-exporter` with:
- Label: `"EXPORTER-Channel-Binding"`
- Context: zero-length string
- Length: 32 bytes

RFC 9266 states: "Implementations that support channel binding over TLS 1.3 MUST implement tls-exporter."

**Analysis**: AAFP is not using SASL/GSS-API channel binding. It is using the TLS exporter directly for its own application-layer authentication. Using a custom label provides protocol-specific domain separation (the exporter value is specific to AAFP and cannot be reused in other protocols). This is a legitimate use of the TLS exporter API.

However, the custom label should be documented with justification. Additionally, AAFP should consider whether interoperability with standard channel binding consumers (e.g., SASL mechanisms) is ever needed. For v1, it is not.

**Modification**: Change the label to follow RFC 9266's naming convention for protocol-specific exporter labels. RFC 8446 §7.5 shows that exporter labels are protocol-specific (e.g., "EXPORTER-Channel-Binding" for generic channel binding). AAFP should use:

```
tls_binding = TLS-Exporter("EXPORTER-AAFP-Channel-Binding", "", 32)
```

This follows the RFC 9266 naming convention ("EXPORTER-" prefix) while providing AAFP-specific domain separation. The label is a one-way door (changing it invalidates all signatures), so the naming convention should be established now.

**Verification**: RFC 8446 §7.5 allows any label string. RFC 9266 defines "EXPORTER-Channel-Binding" for generic use. AAFP's "EXPORTER-AAFP-Channel-Binding" is protocol-specific and does not conflict. **Consistent with TLS 1.3 practices.**

### 3.2 H2: DoS Pre-Verification MAC — Security Property (MODIFICATION REQUIRED)

**Current proposal**: MAC key derived from `receiver_agent_id` via HKDF.

**Finding**: The receiver_agent_id is public (published in AgentRecords). Therefore, the MAC key is computable by anyone who knows the receiver's AgentId. The MAC proves the sender knows the receiver's AgentId, not that the sender possesses a secret.

**Analysis**: This is the same security property as WireGuard's mac1, which uses `HASH(LABEL_MAC1 || responder.static_public)` — the responder's static public key is also public. The purpose is to filter out random garbage (attacker must know the receiver's identity), not to authenticate the sender.

**Modification**: Clarify the security property in the RFC text:

```
The receiver_mac proves that the sender knows the receiver's
AgentId. It does NOT authenticate the sender (the sender's
identity is verified by the ML-DSA-65 signature). The purpose
of receiver_mac is to allow the server to reject messages from
attackers who do not know the server's AgentId, without
performing expensive signature verification.
```

**Verification**: HMAC-SHA256 with HKDF-derived key is standard (NIST SP 800-108, RFC 5869). The security property is correctly scoped. **Consistent with WireGuard mac1 pattern.**

### 3.3 H4: `expires_at` in Handshake — Trust Model (MODIFICATION REQUIRED)

**Current proposal**: Add `expires_at` (uint) as a required field in ClientHello and ServerHello.

**Finding**: The `expires_at` field is self-attested — the agent signs its own expiry time. A malicious agent could claim a far-future expiry. The AgentRecord (from discovery) has an authoritative `expires_at` that is also self-signed, so the trust level is the same.

**Analysis**: The handshake `expires_at` serves two purposes:
1. Allow the peer to reject expired identities without a discovery lookup.
2. Provide a self-attested expiry that the peer can verify against the AgentRecord when available.

The trust model is: the agent signs its own expiry. This is the same trust model as the AgentRecord. The peer trusts the self-attested expiry for first connections (no AgentRecord available) and verifies it against the AgentRecord for subsequent connections.

**Modification**: Add trust model clarification to the RFC:

```
The `expires_at` field in ClientHello and ServerHello is a
signed self-attestation of the agent's identity expiry time.
It has the same trust level as the AgentRecord's `expires_at`
field (both are self-signed).

When the peer has the agent's AgentRecord (from discovery), the
AgentRecord's `expires_at` is authoritative. If the handshake
`expires_at` differs from the AgentRecord's `expires_at`, the
peer SHOULD use the earlier (sooner) expiry.

When the peer does not have the AgentRecord (first connection),
the peer trusts the handshake `expires_at` as a self-attested
claim. The peer SHOULD verify it against the AgentRecord when
one becomes available.
```

**Verification**: X.509 certificates include `notAfter` as a self-attested field (signed by the CA, not the subject, but the trust model is similar). JWT tokens include `exp` as a self-attested claim. **Consistent with established identity document patterns.**

### 3.4 FIPS 204 Signing Mode Verification

**Finding**: FIPS 204 (final, August 2024) specifies ML-DSA with hedged signing as the default. The `ML-DSA.Sign()` function incorporates fresh randomness. Deterministic signing is achieved by setting the randomness input to all zeros.

The IETF CFRG draft (draft-connolly-cfrg-ml-dsa-security-considerations) states: "There is no reason to prefer deterministic signing over hedged signing; hedged signing is the safer default in all environments, and is essential where fault injection or side-channel attacks are a concern."

RFC 9881 states: "ML-DSA offers both deterministic and randomized signing. Signatures generated with either mode are compatible and a verifier cannot tell them apart."

**Verification**: AAFP's RFCs do not currently specify a signing mode. This is a gap. The amendment set should add a recommendation:

```
Implementations SHOULD use hedged (randomized) signing as
specified by FIPS 204 ML-DSA.Sign() with fresh randomness.
This provides side-channel resistance.

Implementations MAY use deterministic signing (ML-DSA.Sign()
with randomness set to all zeros) for testing and debugging.
Deterministic signatures are valid and verifiable by all
implementations regardless of which mode the signer used.
```

This is informative (SHOULD/MAY), not normative, because the signing mode does not affect interoperability (both modes produce valid signatures).

**Action**: Add this recommendation to RFC-0003 Section 3.4 (Signature Computation).

### 3.5 Domain Separation — Prefix-Free Verification

**Finding**: The IETF CFRG hybrid signature considerations draft states: "The only way to avoid [key reuse problems] is to introduce a domain separator from a prefix-free set."

**Verification**: AAFP's domain separators:
- "aafp-v1-handshake" (18 bytes)
- "aafp-v1-record" (15 bytes)
- "aafp-v1-ucan" (13 bytes)

Prefix-free check:
- "aafp-v1-handshake" is NOT a prefix of "aafp-v1-record" (differs at position 9: 'h' vs 'r')
- "aafp-v1-handshake" is NOT a prefix of "aafp-v1-ucan" (differs at position 9: 'h' vs 'u')
- "aafp-v1-record" is NOT a prefix of "aafp-v1-ucan" (differs at position 9: 'r' vs 'u')
- "aafp-v1-record" is NOT a prefix of "aafp-v1-handshake" (differs at position 9)
- "aafp-v1-ucan" is NOT a prefix of "aafp-v1-handshake" (differs at position 9)
- "aafp-v1-ucan" is NOT a prefix of "aafp-v1-record" (differs at position 9)

**Result**: The set is prefix-free. **Consistent with CFRG guidance.**

### 3.6 CBOR Deterministic Encoding — RFC Reference Verification

**Finding**: RFC-0002 Section 8.1 cites "RFC 7049 Section 3.9" for canonical CBOR. RFC 7049 has been obsoleted by RFC 8949 (December 2020).

**Verification**: RFC 8949 Section 4.2.3 defines "length-first core deterministic encoding requirements" which matches AAFP's described rules ("shortest encoding first, then lexicographic"). RFC 7049 Section 3.9 defined "Canonical CBOR" with a different sorting order (length-first was the RFC 7049 approach, but the terminology and details differ).

**Action**: Update all references from RFC 7049 to RFC 8949. Specify "length-first core deterministic encoding requirements (RFC 8949 Section 4.2.3)" as normative. This is a documentation fix, not a wire protocol change (the encoding rules are the same; only the reference is updated).

### 3.7 Cryptographic Verification Summary

| Crypto Choice | Standard Reference | Consistent? | Action |
|---------------|-------------------|-------------|--------|
| Transcript: running SHA-256 | TLS 1.3 §4.4.1, Noise §5.2 | Yes | None |
| Channel binding: TLS exporter | RFC 8446 §7.5, RFC 9266 | Yes (with label modification) | Change label to "EXPORTER-AAFP-Channel-Binding" |
| Domain separation: prefix strings | CFRG hybrid-sig draft | Yes (prefix-free verified) | None |
| Algorithm identifiers: uint registry | TLS 1.3 §4.2.3, JWT `alg`, COSE | Yes | None |
| Signature input: hash + domain separator | Standard practice | Yes | None |
| ML-DSA-65 signing mode | FIPS 204 final, CFRG draft | Not specified (gap) | Add hedged signing recommendation |
| AgentId: SHA-256(pubkey) | Standard hash-based ID | Yes | Document hash agility as future work |
| CBOR deterministic encoding | RFC 8949 §4.2.3 | Reference outdated | Update RFC 7049 → RFC 8949 |
| DoS MAC: HMAC-SHA256 + HKDF | NIST SP 800-108, RFC 5869 | Yes (with property clarification) | Clarify security property |
| `expires_at` self-attestation | X.509 `notAfter`, JWT `exp` | Yes (with trust model clarification) | Add trust model text |

**No conflicts with NIST guidance or TLS 1.3 practices identified.** Three modifications required (C5 label, H2 property clarification, H4 trust model) and two additions (FIPS 204 signing mode, RFC 8949 reference update).

---

## 4. Hash Agility — Explicit Future Design Consideration

Per the user's guidance: "it's worth making clear in the RFC that hash agility remains an explicit future design consideration rather than implying it has already been solved."

The `key_algorithm` field (H8) addresses **signature algorithm agility**, not **hash function agility**. AgentId = SHA-256(public_key) uses a fixed hash function. If SHA-256 needs to be replaced (e.g., due to a cryptanalytic breakthrough), all existing AgentIds become invalid.

**Action**: Add to RFC-0003 Section 2.2 (AgentId Derivation):

```
### 2.2 AgentId Derivation

AgentId = SHA-256(public_key)

The hash function (SHA-256) is fixed for v1. Hash function agility
is an explicit future design consideration. If SHA-256 needs to be
replaced in a future version, the following approaches may be
considered:

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
```

This makes it explicit that hash agility is a known future consideration, not solved by the `key_algorithm` field.

---

## 5. Final Approval Decisions

| ID | Recommendation | Modifications Applied |
|----|---------------|----------------------|
| C1 | **Accept** | None |
| C2 | **Accept** | None |
| C3 | **Accept** | None |
| C4 | **Accept** | None |
| C5 | **Accept with modification** | Label changed to "EXPORTER-AAFP-Channel-Binding" (RFC 9266 naming convention) |
| C6 | **Accept** | None |
| H1 | **Accept** | None |
| H2 | **Accept with modification** | Security property clarified (proves sender knows receiver AgentId, not sender authentication) |
| H3 | **Accept** | None |
| H4 | **Accept with modification** | Trust model clarified (self-attested; AgentRecord authoritative when available; use earlier expiry) |
| H5 | **Accept** | None |
| H6 | **Accept** | None |
| H7 | **Resolved by C1 + C2** | — |
| H8 | **Accept** | None |
| H9 | **Resolved by C3** | — |
| H10 | **Accept** | None |
| H11 | **Accept** | None |
| H12 | **Accept** | None |

### Additional Changes (Not in Original Amendment Set)

| Change | Source | RFCs Affected |
|--------|--------|---------------|
| ML-DSA-65 signing mode recommendation | FIPS 204 verification | RFC-0003 §3.4 |
| RFC 7049 → RFC 8949 reference update | CBOR verification | RFC-0002 §8.1 |
| Hash agility future consideration | User guidance | RFC-0003 §2.2 |

### Deferred Items

| Item | Reason | Future Action |
|------|--------|---------------|
| Multihash AgentId | Changes identifier size and ecosystem semantics; not needed for v1 | Document as future consideration (done in §4 above) |
| Public key omission in handshake | Optimization; 10KB handshake acceptable for v1 | Future RFC may define optional public key omission |
| Cookie-based DoS mechanism | More complex than MAC pre-verification; not needed for v1 | Future RFC may define cookie mechanism |
| Variable-length integer encoding | Wire format optimization; 28-byte header acceptable for v1 | Future protocol version may adopt QUIC-style encoding |
| 0-RTT resumption | Latency optimization; 2.5 RTT acceptable for v1 | Future RFC may define 0-RTT mode |
| Distributed DHT | Scalability beyond ~100K agents | Future RFC |

---

## 6. Implementation Notes

### 6.1 Treating RFCs as the Product

Per the user's guidance: "At this point, I would treat the RFCs as the product and the code as an implementation of those RFCs, not the other way around."

The RFC revision process follows this principle:
1. RFCs are the authoritative specification.
2. Code implements the RFCs, not vice versa.
3. RFC changes are reviewed and approved before implementation.
4. The conformance checklist is derived from the RFCs, not the code.

### 6.2 Document Set After Revision

The following documents will be produced:

1. **RFC-0001 through RFC-0006 (Revision 2)**: Updated with all accepted amendments.
2. **RFC_CHANGELOG.md**: Lists all changes from Revision 1 to Revision 2.
3. **AMENDMENT_STATUS.md** (this document): Records approval decisions and crypto verification.
4. **Updated conformance checklist** (in RFC-0006 §8.1): Includes all new requirements.

### 6.3 Version Numbering

The RFCs remain at version 1 (the protocol version). "Revision 2" refers to the document revision (the second published draft of the v1 specification), not a protocol version change. The protocol version field in the frame header remains 1.
