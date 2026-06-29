# RFC-0006: AAFP Versioning & Compatibility

```
Status:         Freeze Candidate (Revision 5)
Number:         0006
Title:          Protocol Versioning, Extension Registry, and
                Compatibility Rules
Author:         AAFP Project
Created:        2025-06-25
Revised:        2025-01-15 (Revision 4: no content changes, version bump
                for consistency with RFC-0002 and RFC-0003)
                2025-01-16 (Revision 5: no content changes, version bump
                for consistency with RFC-0003)
Type:           Standards Track
Obsoletes:      —
Obsoleted by:   —
```

## 1. Overview

This RFC specifies how AAFP protocol versions are numbered, how
extensions are registered, and how implementations handle forward
and backward compatibility. This document is governance — it defines
the rules for evolving the protocol without breaking existing
implementations.

This is a separate RFC from RFC-0002 (Transport & Framing) because
versioning and compatibility rules change frequently over a
protocol's lifetime. Keeping them separate avoids constant revisions
to the wire format specification.

### 1.1 Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 2. Protocol Versioning

### 2.1 Version Numbering

AAFP uses a single 8-bit protocol version field in the frame header
(see RFC-0002 Section 3.1).

```
Version 0:   Pre-RFC (v0.1 MVP). NOT compatible with v1.
Version 1:   First standardized version (RFC-0001 through RFC-0006).
Version 2+:  Future versions. Assigned via this RFC's process.
```

Version 0 is the pre-RFC MVP implementation. It uses a different
frame format and is NOT compatible with version 1. Version 0
implementations MUST NOT claim conformance to this RFC.

### 2.2 Version Negotiation

Protocol version is negotiated via TLS ALPN (see RFC-0002 Section
2.2):

- `aafp/1` → AAFP version 1
- `aafp/2` → AAFP version 2 (future)

If ALPN negotiation fails (no common version), the connection MUST
be closed. There is no in-band version downgrade mechanism.

### 2.3 Version Compatibility Rules

- **Same version**: Implementations MUST be fully compatible with
  the same protocol version.
- **Forward (new sender, old receiver)**: An old receiver MUST
  handle frames from a new sender by:
  1. Reading the version field.
  2. If the version is unknown, sending an ERROR frame with code
     `8006` (INVALID_VERSION) and closing the connection.
  3. If the version is known, processing normally.
  
  Note: Forward compatibility is achieved through extensions (see
  Section 3), not version skipping. A v1 receiver cannot process
  v2 frames.

- **Backward (old sender, new receiver)**: A new receiver MUST
  process frames from an old sender according to the old version's
  rules. The version field in the frame header indicates which
  rules apply.

### 2.4 Version Lifecycle

1. **Draft**: Version is being designed. No implementations.
2. **Proposed**: RFC is complete. Implementations may begin.
3. **Active**: At least two independent implementations pass
   interoperability tests.
4. **Deprecated**: Version is superseded. New implementations
   SHOULD NOT use it. Existing implementations MAY continue.
5. **Retired**: Version is no longer supported. ALPN identifiers
   for retired versions MAY be reassigned.

### 2.5 Specification Lifecycle

The RFC documents have a lifecycle distinct from the protocol
version they specify:

1. **Draft**: RFC is being written and may change significantly.
   No freeze commitment.
2. **Freeze Candidate**: RFC is believed complete. No further
   architectural changes unless an interoperability or security
   issue is discovered. Implementation may begin, but implementers
   should expect minor clarifications.
3. **Proposed**: RFC has passed independent specification review.
   Two or more implementations are in progress.
4. **Stable**: RFC has two or more interoperable implementations
   that pass conformance tests. Changes require a new revision
   with explicit justification.

Current specification status: **Freeze Candidate (Revision 2)**

The RFCs are designated as Candidate Protocol 0.9. The protocol
version field remains 1. The "0.9" designation indicates that the
specification is not yet validated through independent
implementation. Once two independent implementations achieve
interoperability, the specification will advance to Proposed and
the candidate designation will be dropped.

#### Freeze Commitment

During the freeze candidate phase:

- **No new features** will be added to the RFCs.
- **No architectural changes** will be made unless they address a
  genuine interoperability or security issue discovered during
  implementation or review.
- **Clarifications** (improved wording, additional examples, cross-
  reference fixes) MAY be made without a new revision if they do
  not change the normative requirements.
- **Normative changes** require a new revision (Revision 3) and
  must be documented in RFC_CHANGELOG.md with justification.

#### Change Control

All proposed changes to the RFCs during the freeze candidate phase
MUST be documented as an amendment proposal (following the
AMENDMENTS-0001 pattern) and reviewed through the approval gate
process (following the AMENDMENT_STATUS.md pattern) before being
applied.

## 3. Extension Registry

### 3.1 Extension Types

Extensions are identified by a 16-bit type field (see RFC-0002
Section 6.1). The extension type registry:

| Range | Assignment Policy |
|-------|-------------------|
| 0x0000–0x3FFF | Standards-track extensions (assigned via RFC) |
| 0x4000–0x7FFF | Experimental extensions (no assignment needed) |
| 0x8000–0xBFFF | Private-use extensions (no assignment needed) |
| 0xC000–0xFFFF | Reserved (MUST NOT be used) |

### 3.2 Standards-Track Extension Assignment

New standards-track extensions are assigned via the RFC process:

1. An RFC proposes a new extension type and its semantics.
2. The RFC specifies the extension data format.
3. The RFC specifies whether the extension is optional, negotiated,
   or mandatory.
4. The RFC is reviewed and accepted.
5. The extension type is assigned from the 0x0000–0x3FFF range.

### 3.3 Experimental Extensions

Experimental extensions use types in the 0x4000–0x7FFF range. These
types do not require RFC assignment and MAY be used for testing
and experimentation. Implementations MUST NOT rely on
experimental extensions for production use.

### 3.4 Private-Use Extensions

Private-use extensions use types in the 0x8000–0xBFFF range. These
are for organization-internal use and do not require assignment.
Implementations MUST NOT assume interoperability of private-use
extensions across organizations.

## 4. Frame Type Registry

### 4.1 Frame Types

Frame types are identified by an 8-bit field (see RFC-0002 Section
4). The frame type registry:

| Type | Name | Status | Critical Default |
|------|------|--------|-------------------|
| 0x00 | Reserved | — | — |
| 0x01 | DATA | Active | No |
| 0x02 | HANDSHAKE | Active | Yes |
| 0x03 | RPC_REQUEST | Active | No |
| 0x04 | RPC_RESPONSE | Active | No |
| 0x05 | CLOSE | Active | Yes |
| 0x06 | ERROR | Active | Yes |
| 0x07 | PING | Active | No |
| 0x08 | PONG | Active | No |
| 0x09–0x7F | Reserved | Standards-track | — |
| 0x80–0xFF | Experimental | No assignment needed | — |

### 4.2 Critical Bit

The critical bit (0x80) in the Flags field (see RFC-0002 Section 4)
indicates whether the receiver must understand the frame type:

- **Critical (0x80 set)**: If the receiver does not recognize the
  frame type, it MUST send an ERROR frame with code `8004`
  (UNKNOWN_CRITICAL_FRAME_TYPE) and close the connection.
- **Non-critical (0x80 clear)**: If the receiver does not recognize
  the frame type, it MUST skip the frame and continue processing.

The critical bit default for each frame type is specified in the
registry (Section 4.1). Senders MAY override the default by setting
or clearing the critical bit.

### 4.3 Frame Type Assignment

New frame types in the 0x09–0x7F range are assigned via the RFC
process. Experimental frame types (0x80–0xFF) do not require
assignment.

## 5. Feature Flags

### 5.1 Overview

Feature flags are a 8-bit field in the frame header's Flags byte
(see RFC-0002 Section 3.1). They indicate which optional features
the sender supports.

### 5.2 Defined Feature Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0x80 | CRITICAL | Frame type is critical (see Section 4.2) |
| 0x01 | MORE | More fragments follow (DATA frames) |
| 0x02 | COMPRESSED | Payload is compressed |
| 0x04 | ENCRYPTED | Payload is application-layer encrypted |
| 0x08 | ACK | Frame is an acknowledgment |
| 0x10–0x40 | Reserved | MUST be 0. MUST be ignored by receivers. |

### 5.3 Feature Negotiation

Feature flags are negotiated during the handshake (see RFC-0003
Section 7). The ClientHello and ServerHello include supported
features in the `extensions` field. Features not negotiated during
the handshake MUST NOT be used in subsequent frames.

### 5.4 Reserved Flags

Reserved flag bits (0x10–0x40) MUST be set to 0 by senders and
MUST be ignored by receivers. This allows future versions to
assign new flag bits without breaking existing implementations.

## 6. Unknown Field Handling

### 6.1 General Rule

Implementations MUST handle unknown fields according to the
following rules:

| Field Type | Handling |
|------------|----------|
| Unknown CBOR map fields | Skip (ignore) |
| Unknown frame types (non-critical) | Skip frame |
| Unknown frame types (critical) | Error + close |
| Unknown extension types (non-critical) | Skip extension |
| Unknown extension types (critical) | Error + close |
| Unknown MetadataValue variants | Skip metadata entry |
| Unknown error codes | Use category-based handling |
| Non-zero reserved fields | Ignore |

### 6.2 Security-Sensitive Fields

The following fields MUST NOT be ignored if unknown:

- Authentication-related extensions (critical flag MUST be set)
- Authorization-related extensions (critical flag MUST be set)
- Crypto suite extensions (critical flag MUST be set)

If a critical extension is not recognized, the implementation MUST
reject the frame with error `8005` (UNKNOWN_CRITICAL_EXTENSION).

### 6.3 Strict vs Lenient Parsing

Implementations SHOULD use lenient parsing for metadata and
extension fields (skip unknowns) and strict parsing for
security-critical fields (reject unknowns). The critical bit
mechanism (Section 4.2) allows the sender to specify which handling
is required.

## 7. Compatibility Strategy

### 7.1 Forward Compatibility

Forward compatibility means an old implementation can process
messages from a new implementation. AAFP achieves forward
compatibility through:

1. **Reserved fields**: Reserved bits and bytes in the frame header
   are ignored by old implementations.
2. **Unknown field skipping**: Old implementations skip unknown
   CBOR map fields.
3. **Extension mechanism**: New features are added as extensions,
   which old implementations skip (if non-critical) or reject (if
   critical).
4. **Feature flags**: New features use reserved flag bits, which
   old implementations ignore.

### 7.2 Backward Compatibility

Backward compatibility means a new implementation can process
messages from an old implementation. AAFP achieves backward
compatibility through:

1. **Version field**: The new implementation reads the version
   field and applies the old version's rules.
2. **Optional fields**: New fields in CBOR structures are optional
   (e.g., `metadata` in CapabilityDescriptor). Old messages
   without these fields are valid.
3. **Extension absence**: Old messages do not include extensions.
   The new implementation handles their absence gracefully.

### 7.3 Mandatory Extensions

An extension becomes mandatory when:

1. It is assigned a standards-track extension type (0x0000–0x3FFF).
2. An RFC declares it mandatory for a specific protocol version.
3. The critical bit is always set for the extension.

Mandatory extensions MUST be implemented by all conforming
implementations of the specified protocol version. Non-conforming
implementations MUST negotiate a lower protocol version or fail
the connection.

### 7.4 Deprecation Policy

Fields, extensions, or frame types may be deprecated:

1. **Deprecation notice**: An RFC marks the feature as deprecated.
2. **Grace period**: The feature remains in the registry for at
   least one major version cycle.
3. **Removal**: The feature is removed in a new major version.
   Implementations of the new version MUST NOT send the deprecated
   feature. Implementations MAY accept the deprecated feature for
   backward compatibility.

Deprecated features MUST NOT be removed within the same major
version. Removal requires a new protocol version (e.g., v1 → v2).

## 8. Implementation Conformance

### 8.1 Conformance Requirements

An implementation conforms to AAFP version 1 if it:

1. Uses QUIC version 1 as the transport.
2. Negotiates ALPN `aafp/1` during TLS handshake.
3. Offers `X25519MLKEM768` for TLS key exchange.
4. Uses the frame format specified in RFC-0002 Section 3.
5. Derives AgentId as `SHA-256(public_key)` (fixed SHA-256 for v1).
6. Serializes AgentRecord as CBOR per RFC-0003 Section 3.
7. Uses CapabilityDescriptor per RFC-0003 Section 4.
8. Handles unknown fields per Section 6 of this RFC.
9. Returns protocol errors per RFC-0005.
10. Supports all frame types in Section 4.1 of this RFC.
11. Supports the PING/PONG keepalive mechanism.
12. Supports the CLOSE frame for connection termination.
13. Computes the TLS channel binding value and includes it in the
    handshake transcript hash (per RFC-0002 Section 5.6).
14. Uses domain separators in all signature computations (per
    RFC-0003 Section 3.5).
15. Includes the `key_algorithm` field in ClientHello, ServerHello,
    and AgentRecord (per RFC-0003 Section 2.3). MUST support
    ML-DSA-65 (algorithm 1).
16. Includes the `expires_at` field in ClientHello and ServerHello
    (per RFC-0002 Sections 5.3, 5.4).
17. Uses integer keys for all CBOR structures (per RFC-0002 Section
    8.4).
18. Computes the Session ID using the normative HKDF derivation
    (per RFC-0002 Section 5.7).
19. Uses the handshake extension negotiation protocol (per
    RFC-0002 Section 6.4).

### 8.2 Conformance Testing

Conformance is verified through:

1. **Interoperability testing**: Two independent implementations
   successfully exchange messages.
2. **Wire format validation**: An implementation produces frames
   that conform to the byte-level specification.
3. **Error handling validation**: An implementation correctly
   handles malformed inputs and produces correct error frames.

## 9. Security Considerations

### 9.1 Downgrade Attacks

Version negotiation via ALPN is protected by TLS integrity
protection. An active attacker cannot modify the ALPN negotiation
without being detected by TLS.

Implementations MUST NOT fall back to a lower version if the
requested version is not supported. If no common version exists,
the connection MUST fail.

### 9.2 Extension Security

Critical extensions MUST be understood by the receiver. This
prevents an attacker from stripping security-critical extensions
(e.g., authorization tokens) by claiming not to understand them.

Non-critical extensions MAY be skipped. This allows optional
features to be ignored without breaking the connection.

### 9.3 Reserved Field Abuse

Reserved fields MUST be set to 0 by senders. A non-zero reserved
field MAY indicate a buggy or malicious implementation. Receivers
MAY log this as a warning but MUST NOT fail the connection (this
allows future versions to assign reserved fields).

## 10. IANA Considerations

This RFC defines the following registries:

- **AAFP Protocol Versions**: 0 (pre-RFC), 1 (this RFC), 2+ (future)
- **AAFP Frame Types**: 0x00–0xFF (see Section 4)
- **AAFP Extension Types**: 0x0000–0xFFFF (see Section 3)
- **AAFP Feature Flags**: 0x00–0xFF (see Section 5)
- **AAFP Error Codes**: 0x0000–0xFFFF (see RFC-0005)
- **AAFP Key Algorithm Registry**: Values 1–255 (see RFC-0003
  Section 2.3)
- **AAFP Domain Separators**: "aafp-v1-handshake", "aafp-v1-record",
  "aafp-v1-ucan" (see RFC-0003 Section 3.5)
- **AAFP Handshake Extension Types**: 0x0001–0x3FFF (see RFC-0002
  Section 6.4)

All registries use the assignment policies specified in this RFC.

## 11. Governance

### 11.1 RFC Lifecycle

AAFP RFCs follow the specification lifecycle defined in Section 2.5:

1. **Draft** → **Freeze Candidate** → **Proposed** → **Stable**

Transitions require:
- Draft → Freeze Candidate: Internal review complete, no known
  architectural issues.
- Freeze Candidate → Proposed: Independent specification review
  complete, at least one implementation in progress.
- Proposed → Stable: Two or more interoperable implementations
  pass conformance tests.

### 11.2 Amendment Process

Changes to Stable or Freeze Candidate RFCs MUST follow the
amendment process:

1. **Amendment proposal**: Document the issue, proposed change,
   rationale, affected RFCs, wire protocol impact, backward
   compatibility analysis, and answers to the four architecture
   questions (see AMENDMENTS-0001 for the template).
2. **Approval gate**: Produce an impact matrix identifying
   normative/informative status, wire changes, crypto changes,
   backward compatibility, version impact, risk of future regret,
   and recommendation (Accept/Defer/Reject). Identify one-way
   doors. Verify cryptographic choices against current standards.
3. **Application**: Apply only approved amendments. Generate
   updated RFCs, RFC_CHANGELOG.md, and AMENDMENT_STATUS.md.
4. **Revision**: New RFC revision (e.g., Revision 2 → Revision 3)
   with changelog entry.

### 11.3 Security Disclosure Process

Security vulnerabilities in the AAFP protocol or reference
implementation SHOULD be reported through the following process:

1. **Report**: Report vulnerabilities privately to the AAFP
   project maintainers. Do not publicly disclose until a fix is
   available.
2. **Acknowledgment**: Maintainers acknowledge receipt within 48
   hours.
3. **Assessment**: Maintainers assess the severity and impact
   within 7 days.
4. **Fix**: A fix is developed. For protocol-level vulnerabilities,
   an amendment proposal is drafted following Section 11.2.
5. **Disclosure**: Coordinated disclosure after the fix is
   available. A security advisory is published describing the
   vulnerability, affected versions, and mitigation.

Until a formal security contact is established, reports SHOULD be
sent through the project's private GitHub security advisories
feature.

### 11.4 Compatibility Policy

- **Same major version**: Implementations MUST be wire-compatible.
  Changes within a major version MUST be backward compatible (new
  fields are optional, existing fields retain semantics).
- **Cross major version**: No compatibility required. Migration
  paths SHOULD be documented but are not mandated.
- **Extension compatibility**: New extensions MUST NOT break
  implementations that do not support them (per Section 6.1).

### 11.5 Conformance Test Suite

A conformance test suite SHALL be maintained to validate
implementations against the RFCs. The test suite:

- Is derived from the normative requirements in the RFCs (not from
  any particular implementation).
- Tests wire format compliance, handshake correctness, error
  handling, and extension negotiation.
- Is versioned alongside the RFCs.
- MUST be used to validate any implementation claiming conformance
  to a given AAFP version.

The conformance test suite is out of scope for the current RFC
series but will be specified in a future RFC once the reference
implementation is complete.

## 12. References

- RFC 2119: Key words for use in RFCs
- RFC 7301: Transport Layer Security (TLS) Application-Layer
  Protocol Negotiation Extension (ALPN)
- RFC-0001: AAFP Protocol Overview
- RFC-0002: AAFP Transport & Framing
- RFC-0003: AAFP Identity & Authentication
- RFC-0005: AAFP Error Model
