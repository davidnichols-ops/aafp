# AAFP Specification Ambiguities Register

This document tracks ambiguities, underspecifications, and contradictions
discovered during independent implementation and interoperability testing.
Each entry must be resolved in RFC Revision 4 before the protocol is
declared frozen.

## SA-0001: CapabilityDescriptor metadata field presence

**Status**: Resolved in RFC Revision 4
**Discovered**: During Go independent implementation (Phase 3, Task 6)
**Severity**: High — breaks signature verification across implementations
**RFC Reference**: RFC-0003 §4.2, §4.4

### Description

RFC-0003 §4.2 defines the CapabilityDescriptor CBOR schema as:

```cbor
CapabilityDescriptor = {
    1: tstr,                    // "name": capability name
    2: { *tstr => MetadataValue },  // "metadata": optional
}
```

RFC-0003 §4.4 Field Semantics states:

| Key | Name | Type | Required | Description |
|-----|------|------|----------|-------------|
| 1 | name | tstr | Yes | Capability name |
| 2 | metadata | map | No | Optional metadata. May be absent or empty. |

The phrase "May be absent or empty" is ambiguous. It permits two
valid encodings of a CapabilityDescriptor with no metadata:

1. **Omit key 2 entirely**: `{1: "inference"}` → CBOR: `a10169696e666572656e6365`
2. **Include key 2 as empty map**: `{1: "inference", 2: {}}` → CBOR: `a20169696e666572656e636502a0`

These produce different CBOR byte sequences. Since AgentRecord
signatures are computed over the canonical CBOR encoding of the
record (which includes CapabilityDescriptors), two implementations
making different choices will produce different signature inputs,
causing signature verification to fail even when both sides hold
valid keys.

### Evidence

The Rust reference implementation (aafp-identity) always includes
key 2 as an empty map (`Value::StrMap(vec![])`) when metadata is
empty. The Go independent implementation, following the "May be
absent" reading, initially omitted key 2. This caused the
`discovery_announce_params` test vector to fail with a hash
mismatch. The Go implementation was adjusted to match Rust, but
this adjustment was made by consulting Rust source code — exactly
what an independent implementation should not need to do.

### Impact

- Any implementation that omits key 2 will produce AgentRecord
  signatures that fail verification on implementations that include
  it, and vice versa.
- The test vectors (TEST_VECTORS.md) implicitly encode the Rust
  choice (always include key 2), but the RFC does not mandate this.
- An implementer following the RFC alone cannot determine which
  encoding to use.

### Proposed Resolution

**Option A (recommended)**: Amend RFC-0003 §4.4 to state that key 2
(metadata) is REQUIRED and MUST be encoded as an empty map (`a0`)
when there are no metadata entries. Update the schema in §4.2 to
remove the "optional" comment. This is the simpler rule: the field
is always present, reducing implementation variance.

**Option B**: Amend RFC-0003 §4.4 to state that key 2 (metadata)
MAY be omitted when empty, and that signature verification MUST
normalize by treating absent key 2 as equivalent to an empty map.
This requires verifiers to re-encode with key 2 present before
computing the signature input, adding complexity.

Option A is recommended because it produces a single canonical
encoding with no normalization step required.

### Resolution (RFC Revision 4, 2025-01-15)

**Option A adopted.** RFC-0003 §4.4 now states that key 2 (metadata)
MUST always be present. An empty metadata map MUST be encoded as
`a0` (empty CBOR map), not omitted. The schema in §4.2 has been
updated to reflect this. No wire format change for implementations
that already include key 2.

### Affected Test Vectors

- `discovery_announce_params` (TEST_VECTORS.md)
- Any future test vector involving CapabilityDescriptor with empty
  metadata

### Notes

This ambiguity was not caught during RFC review because the Rust
implementation made a consistent (but unspecified) choice. It was
only exposed when an independent implementation made a different
valid choice. This demonstrates the value of independent
implementation as a validation technique.

---

## SA-0002: Empty CBOR map key-type ambiguity in typed contexts

**Status**: Resolved in RFC Revision 4
**Discovered**: During Go→Rust interop fixture verification (Phase 3)
**Severity**: Medium — causes decoder rejection of valid empty maps
**RFC Reference**: RFC-0001 §3 (CBOR), RFC-0003 §4.2 (CapabilityDescriptor)

### Description

CBOR encodes maps with a major type (5 for int-keyed, 6 for
string-keyed) but does not encode the *expected* key type beyond the
keys actually present. When a map is empty (`a0`), there is no way
to distinguish whether it was intended as `map<int, T>` or
`map<string, T>` — both encode to the same byte `0xa0`.

This becomes a problem when a decoder needs to interpret an empty
map in a typed context. For example, the `CapabilityDescriptor`
metadata field (key 2) is defined as `map<string, MetadataValue>`.
When metadata is empty, the field is encoded as `a0`. A decoder
that checks the CBOR major type to determine whether the map is
int-keyed or string-keyed will see an int-keyed map (major type 5)
for an empty map, because CBOR's `a0` is major type 5 (int-keyed
empty map). This causes the decoder to reject the field as a type
mismatch, even though the encoding is valid per the schema.

### Evidence

During Go→Rust interop verification, the Go implementation encoded
an empty metadata map as `a0` (CBOR major type 5). The Rust
decoder, checking for string-keyed maps (major type 6), rejected
this as a type mismatch. The Go decoder was adjusted to treat
empty maps in known string-keyed contexts as string-keyed, but
this required schema-level knowledge that the RFC does not
explicitly state should be applied.

### Impact

- Any protocol field defined as `map<string, T>` that can be empty
  will produce `a0` on the wire, which decoders may interpret as
  either int-keyed or string-keyed.
- Decoders that strictly check CBOR major types will reject valid
  empty string-keyed maps.
- This affects `CapabilityDescriptor.metadata` and any future
  string-keyed map fields.

### Proposed Resolution

**Schema-driven key-type interpretation**: The RFC should state
that for each protocol field, the expected map key type is defined
by the enclosing schema, not by the CBOR major type of the encoded
data. Specifically:

- A field defined as `map<string, T>` MUST be interpreted as a
  string-keyed map, even if encoded as an empty CBOR map (`a0`).
- A field defined as `map<uint, T>` MUST be interpreted as an
  integer-keyed map, even if encoded as an empty CBOR map (`a0`).
- Decoders MUST use the schema-defined key type when interpreting
  empty maps, not the CBOR major type.

This avoids creating a CBOR-specific exception and instead makes
the interpretation part of the protocol schema. It aligns with
how typed serialization frameworks (e.g., serde with explicit
type annotations) handle empty maps.

### Resolution (RFC Revision 4, 2025-01-15)

**Schema-driven key-type interpretation adopted.** RFC-0002 §8.1
now states that for AAFP fields with a schema-defined key type,
the key type MUST be determined from the enclosing schema, not
from the CBOR major type of the encoded data. A field defined as
`map<tstr, T>` MUST be interpreted as string-keyed even when empty
(`a0`); a field defined as `map<uint, T>` MUST be interpreted as
integer-keyed even when empty. RFC-0003 §4.5 cross-references this
rule for the CapabilityDescriptor metadata field. No wire format
change — this is a decoder behavior clarification only.

### Affected Components

- `CapabilityDescriptor.metadata` (RFC-0003 §4.2)
- Any future `map<string, T>` field in the protocol

### Notes

This is a general CBOR issue, not specific to AAFP. However, since
AAFP uses CBOR for all structured data and defines schemas with
specific key types, the RFC must clarify how empty maps are
interpreted. The schema-driven approach is preferred over a
CBOR-level rule because it keeps the interpretation in the
protocol layer.

---

## SA-0003: AgentRecord 30-day expiry — warning vs. rejection

**Status**: Resolved in RFC Revision 5
**Discovered**: During implementation review of AgentRecord verification
**Severity**: Medium — implementation/spec mismatch; potential for
divergent verify() behavior across implementations
**RFC Reference**: RFC-0003 §8.4, §3.6

### Description

RFC-0003 §8.4 stated:

> "Implementations MUST support AgentRecord expiry no longer than
> 30 days (2,592,000 seconds). Implementations MUST warn users if
> an AgentRecord's `expires_at` exceeds 30 days from the current
> time."

This text was ambiguous on two points:

1. **Warning vs. rejection**: The phrase "MUST support expiry no
   longer than 30 days" was misreadable as a verification-rejection
   requirement. However, the normative verification procedure in §3.6
   (8 steps) contains no 30-day rejection step — only past-expiry
   rejection at step 6 (`expires_at <= current_time` → error 2002).
   No error code exists for "expiry too long." The originating review
   (REVIEW-0004 TC1) and amendment (AMENDMENTS-0002 A-T3) both
   specified "MUST warn users," not "MUST reject."

2. **Predicate basis**: §8.4 says "exceeds 30 days from the current
   time," implying `expires_at - current_time > 30 days`. The existing
   Rust helper `exceeds_max_expiry()` used `expires_at - created_at`
   (total record lifetime), which is a different predicate.

### Evidence

Four independent lines of evidence confirmed the warning-only intent:

1. §3.6 (normative verification procedure) has no 30-day rejection step.
2. The rule lives exclusively in §8.4 (Security Considerations) and
   §9.6 (descriptive), never in §3.6, §3.3, RFC-0004, or RFC-0006
   conformance requirements.
3. No error code exists for "expiry too long" in RFC-0005 §3.3.
4. REVIEW-0004 TC1 and AMENDMENTS-0002 A-T3 both use "MUST warn
   users," not "MUST reject."

### Impact

- An implementation that rejects >30-day records in `verify()` would
  be stricter than the specification and would diverge from
  implementations that follow §3.6 as written.
- The `created_at`-based predicate would fire warnings for records
  with long total lifetime even when little future lifetime remains,
  and fail to warn for records with short total lifetime but far-future
  expiry (e.g., created long ago with a fresh expiry).

### Resolution (RFC Revision 5, 2025-01-16)

**Warning-only interpretation adopted.** RFC-0003 §8.4 point 1 now
states explicitly that the 30-day limit is a deployment mitigation,
not a verification requirement. The verification procedure in §3.6
does NOT reject records whose lifetime exceeds 30 days. The warning
predicate is `expires_at - current_time > 2,592,000`, computed from
the current time, not from `created_at`.

No wire format change, no new error codes, no §3.6 modification.

### Affected Components

- `AgentRecord::verify()` (Rust) — unchanged; confirms it does not
  reject >30-day records (conformance test R5-001)
- `AgentRecord::exceeds_max_expiry_warning(now)` (Rust) — new method
  replacing the buggy `exceeds_max_expiry()` (used `created_at`)
- `AgentRecord.Verify()` (Go) — unchanged
- `AgentRecord.ExceedsMaxExpiryWarning(now)` (Go) — new method

### Affected Test Vectors

None. This clarification does not affect any wire-format or
signature test vector. Conformance tests R5-001 through R5-004
were added to both implementations.

### Notes

This ambiguity was not caught during RFC review because the
verification procedure (§3.6) and the security considerations (§8.4)
were reviewed as separate sections, and the relationship between
the "MUST warn" in §8.4 and the verification algorithm in §3.6 was
not explicitly stated. It was exposed during implementation review
when the `exceeds_max_expiry()` helper was found to use a different
predicate than §8.4 specifies.
