# REVIEW-0004: Formal Threat Model Review

**Review Date**: 2025-06-25
**Reviewer**: Security reviewer performing formal threat model analysis
**RFCs Reviewed**: RFC-0001 through RFC-0006 (Freeze Candidate Revision 2)
**Review Standard**: IETF / QUIC WG / libp2p maintainers level

## Executive Summary

The AAFP protocol demonstrates strong cryptographic foundations with post-quantum cryptography by default (ML-DSA-65, X25519MLKEM768). However, the trust model is not clearly articulated, several partial compromise scenarios are inadequately addressed, and key management gaps exist. The protocol explicitly defers several security mechanisms (revocation, Sybil resistance) to future RFCs, which creates identifiable security boundaries.

**Overall Assessment**: The protocol is suitable for controlled environments (private networks, authenticated deployments) but requires additional security measures for adversarial public deployments.

## Findings by Severity

### CRITICAL (2)

| # | ID | Title | Location |
|---|----|-------|----------|
| 1 | TC1 | No revocation mechanism for compromised ML-DSA-65 keys | RFC-0003 §8.4 |
| 2 | TC2 | Key management gaps (storage, rotation, compromise response) | RFC-0003 §8 |

### HIGH (8)

| # | ID | Title | Location |
|---|----|-------|----------|
| 3 | TH1 | Trust model not clearly stated | RFC-0001 §9, RFC-0003 §8, RFC-0004 §8 |
| 4 | TH2 | Bootstrap node compromise: eclipse attacks and identity enumeration | RFC-0004 §3.1, §3.4, §8.4 |
| 5 | TH3 | UCAN delegation chain compromise blast radius | RFC-0003 §5.5, §8.5 |
| 6 | TH4 | MITM on first connection (TOFU vulnerability) | RFC-0001 §9.5, RFC-0003 §8.3 |
| 7 | TH5 | DoS mitigations partial (pre-verification optional) | RFC-0002 §5.8, RFC-0004 §3.4 |
| 8 | TH6 | Bootstrap node information learning (privacy) | RFC-0004 §3.2, §8.5 |
| 9 | TH7 | Application-layer identity has no forward secrecy | RFC-0003 §2.1, §5.4 |
| 10 | TH8 | Key storage requirements not specified | RFC-0003 §8 |

### MEDIUM (6)

| # | ID | Title | Location |
|---|----|-------|----------|
| 11 | TM1 | TLS compromise exposes all traffic (no app-layer encryption) | RFC-0001 §5.3, RFC-0003 §8.1 |
| 12 | TM2 | Replay attacks: ClientHello replay for DoS | RFC-0002 §5.6, RFC-0003 §8.2 |
| 13 | TM3 | Network partition not addressed | — |
| 14 | TM4 | AgentId correlation across sessions | RFC-0001 §3.1, RFC-0003 §2.1 |
| 15 | TM5 | Bootstrap node information learning (privacy) | RFC-0004 §3.2, §8.5 |
| 16 | TM6 | Implicitly out-of-scope items should be documented | Various |

### LOW (2)

| # | ID | Title | Location |
|---|----|-------|----------|
| 17 | TL1 | Traffic analysis: handshake size fingerprinting | RFC-0003 §2.4, RFC-0002 §5.3/5.4 |
| 18 | TL2 | Session metadata forward secrecy depends on TLS | RFC-0002 §5.7, RFC-0003 §6.2 |

### INFORMATIONAL (5)

| # | ID | Title | Location |
|---|----|-------|----------|
| 19 | TI1 | ML-DSA-65 security assumption (128-bit quantum) | RFC-0001 §5.2, RFC-0003 §2.4 |
| 20 | TI2 | SHA-256 collision resistance assumption | RFC-0001 §3.1, RFC-0002 §5.6 |
| 21 | TI3 | X25519MLKEM768 hybrid security assumption | RFC-0001 §5.2, RFC-0002 §2.3 |
| 22 | TI4 | TLS 1.3 exporter security assumption | RFC-0002 §2.5, RFC-0003 §8.1 |
| 23 | TI5 | HKDF security assumption | RFC-0002 §5.7, §5.8 |

## Detailed Findings

### TC1: No revocation mechanism for compromised ML-DSA-65 keys

**Severity**: CRITICAL
**Location**: RFC-0003 §8.4

**Description**: If an agent's ML-DSA-65 secret key is compromised:
- The attacker can impersonate the agent to all peers
- The attacker can sign valid AgentRecords
- The attacker can sign valid UCAN tokens and delegate capabilities
- The attacker can advertise false capabilities in the DHT
- Existing sessions are NOT compromised (they use TLS-derived session keys)

**Mitigations specified**: Short AgentRecord expiry (RECOMMENDED: 30 days), frequent renewal (RECOMMENDED: every 7 days), applications MAY implement out-of-band revocation lists.

**Gap**: No in-protocol revocation mechanism. Compromised keys remain valid until `expires_at`.

**Recommendation**:
- Document the blast radius explicitly in Security Considerations
- Add normative requirement: "Implementations MUST support AgentRecord expiry no longer than 30 days"
- Add normative requirement: "Implementations MUST warn users if AgentRecord expiry exceeds 30 days"
- Accelerate the revocation mechanism RFC (currently deferred)

### TC2: Key management gaps

**Severity**: CRITICAL
**Location**: RFC-0003 §8

**Description**: No requirements for:
- Secret key protection at rest
- Secret key protection in memory
- Key access controls
- Key export restrictions
- Key rotation procedures (deferred to future RFC)
- Compromise detection and notification

**Recommendation**:
- Add key storage requirements: "Implementations MUST protect ML-DSA-65 secret keys at rest using encryption"
- Add: "Implementations SHOULD use hardware-backed key storage when available"
- Add key compromise response procedures
- Document key rotation as a critical gap with out-of-band best practices

### TH1: Trust model not clearly stated

**Severity**: HIGH
**Location**: RFC-0001 §9, RFC-0003 §8, RFC-0004 §8

**Description**: Trust assumptions are scattered across multiple RFCs without a unified articulation. The trust anchor (agent's own ML-DSA-65 secret key) is never explicitly stated. No trusted third parties exist in v1, but this is not documented.

**Recommendation**: Add a dedicated "Trust Model" section to RFC-0001 that explicitly states:
- Trust anchor: Agent's own ML-DSA-65 secret key
- No trusted third parties in v1
- Bootstrap nodes are trusted by configuration (out-of-band)
- All identity claims are self-attested
- Trust boundaries: what requires out-of-band verification

### TH2: Bootstrap node compromise

**Severity**: HIGH
**Location**: RFC-0004 §3.1, §3.4, §8.4

**Description**: A compromised bootstrap node can:
- Perform eclipse attacks (return only attacker-controlled peers)
- Enumerate all connecting agents' identities
- Inject false AgentRecords into the DHT
- Reject legitimate announcements

**Recommendation**:
- Add normative requirement: "Implementations MUST support configuring multiple bootstrap nodes"
- Add: "Implementations SHOULD use at least 3 bootstrap nodes from different administrative domains"
- Document bootstrap node compromise scenarios

### TH3: UCAN delegation chain compromise

**Severity**: HIGH
**Location**: RFC-0003 §5.5, §8.5

**Description**: A single compromised UCAN token invalidates the entire chain and all downstream delegations. No revocation mechanism exists.

**Recommendation**:
- Add normative requirement: "Implementations MUST enforce a maximum UCAN delegation chain depth of 8"
- Add: "Implementations SHOULD use short UCAN expiry times (RECOMMENDED: 1 hour)"
- Document UCAN token compromise blast radius

### TH4: MITM on first connection (TOFU)

**Severity**: HIGH
**Location**: RFC-0001 §9.5, RFC-0003 §8.3

**Description**: TOFU for TLS certificates allows MITM on first connection. Application-layer signatures and channel binding mitigate but don't eliminate this. AgentId fingerprints enable out-of-band verification but implementations are not REQUIRED to display them.

**Recommendation**:
- Change "SHOULD display" to "MUST display" for AgentId fingerprints on first connection
- Add: "Implementations MUST provide an API for applications to retrieve and compare fingerprints"
- Document the MITM risk on first connection explicitly

### TH5: DoS mitigations partial

**Severity**: HIGH
**Location**: RFC-0002 §5.8, RFC-0004 §3.4

**Description**: DoS pre-verification is optional (MAY), not recommended for Internet-facing deployments. Bootstrap amplification (~500x) is not normatively limited.

**Recommendation**:
- Change DoS pre-verification from "MAY" to "SHOULD" for Internet-facing deployments
- Add: "Bootstrap nodes MUST limit lookup responses to 5 records for unauthenticated requests"
- Add: "Implementations SHOULD enforce maximum concurrent streams per connection"

### TH6: Bootstrap node information learning (privacy)

**Severity**: HIGH (also listed as MEDIUM TM5 from privacy angle)
**Location**: RFC-0004 §3.2, §8.5

**Description**: Bootstrap nodes learn AgentId, public key, capabilities, and endpoints of all connecting agents. No anonymity mechanism in v1.

**Recommendation**: Document explicitly that bootstrap nodes can enumerate all connecting agents. Accelerate private discovery mechanism.

### TH7: Application-layer identity has no forward secrecy

**Severity**: HIGH
**Location**: RFC-0003 §2.1, §5.4

**Description**: AgentRecords and UCAN tokens are self-signed with ML-DSA-65. If the secret key is compromised, all past records and tokens can be forged. No forward secrecy mechanism exists for application-layer identity.

**Recommendation**: Document that application-layer identity does NOT provide forward secrecy. Consider short-lived certificates and key rotation for future versions.

### TH8: Key storage requirements not specified

**Severity**: HIGH
**Location**: RFC-0003 §8

**Description**: No requirements for secret key protection at rest, in memory, or access controls.

**Recommendation**: Add normative requirements for key storage (encryption at rest, hardware-backed when available).

### TM1-TM6, TL1-TL2, TI1-TI5

See executive summary table above. Full details in the threat model analysis.

## Recommendations Priority

### Immediate (Before Freeze)
1. Add dedicated "Trust Model" section to RFC-0001 (TH1)
2. Change "SHOULD display" to "MUST display" for AgentId fingerprints (TH4)
3. Add normative requirement for maximum AgentRecord expiry (30 days) (TC1)
4. Add normative requirement for multiple bootstrap nodes (minimum 3) (TH2)
5. Add normative requirement for maximum UCAN chain depth (8) (TH3)
6. Add "Security Limitations" section documenting implicitly out-of-scope items (TM6)
7. Add key storage requirements (TC2, TH8)
8. Document blast radius of key compromise (TC1)
9. Document application-layer identity forward secrecy gap (TH7)

### High Priority (Before Public Deployment)
1. Add key compromise response procedures (TC2)
2. Change DoS pre-verification to "SHOULD" for Internet-facing deployments (TH5)
3. Add normative requirement for bootstrap lookup limit (5 records) (TH5)
4. Add hedged signing normative recommendation (TI1)
5. Document bootstrap node information learning (TH6)

### Medium Priority (First Major Revision)
1. Accelerate revocation mechanism RFC (TC1)
2. Accelerate key rotation mechanism RFC (TC2)
3. Accelerate private discovery mechanism (TH6)
4. Consider application-layer encryption extension (TM1)
5. Consider handshake padding for traffic analysis resistance (TL1)

## Conclusion

The protocol has strong cryptographic foundations but needs clearer articulation of its trust model, key management requirements, and compromise response procedures before deployment in adversarial environments. The CRITICAL findings (no revocation, key management gaps) are partially mitigated by short expiry times but should be documented as known limitations with explicit normative requirements for mitigations.
