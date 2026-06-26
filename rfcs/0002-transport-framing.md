# RFC-0002: AAFP Transport & Framing

```
Status:         Draft
Number:         0002
Title:          Transport, Framing, Stream Multiplexing, and Wire Format
Author:         AAFP Project
Created:        2025-06-25
Type:           Standards Track
Obsoletes:      —
Obsoleted by:   —
```

## 1. Overview

This RFC specifies the AAFP wire format: how messages are framed on
QUIC streams, how protocol versioning is carried, how extensions are
encoded, and how independent implementations interoperate.

This is the most critical RFC in the AAFP series. It defines what goes
on the wire. Once independent implementations exist, changes to this
document require a new protocol version.

### 1.1 Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

### 1.2 Terminology

- **Frame**: The basic unit of data on an AAFP stream.
- **Stream**: A logical bidirectional or unidirectional communication
  channel, mapped to a QUIC stream.
- **Connection**: A QUIC connection between two agents.
- **Session**: The authenticated, established state of a connection
  after the AAFP handshake completes.
- **Extension**: An optional protocol feature identified by a numeric
  type, carried in the frame header or as a dedicated frame type.

## 2. Transport: QUIC

### 2.1 QUIC Version

AAFP uses QUIC version 1 (RFC 9000). Future versions of QUIC may be
supported via the transport negotiation mechanism (see RFC-0006).

### 2.2 TLS ALPN

AAFP registers the ALPN identifier `aafp/1` for v1 of the protocol.
Implementations MUST negotiate this ALPN identifier during the TLS
handshake. If ALPN negotiation fails, the connection MUST be closed
with a TLS alert.

Future protocol versions register additional ALPN identifiers (e.g.,
`aafp/2`). ALPN negotiation determines which protocol version is in
use for the connection.

### 2.3 TLS Key Exchange

Implementations MUST offer the `X25519MLKEM768` key exchange group
and SHOULD prefer it over classical-only groups. Implementations MAY
offer `X25519` as a fallback for compatibility with implementations
that do not support PQ KEX, but this fallback SHOULD be disabled in
production deployments requiring post-quantum security.

### 2.4 TLS Certificates

Implementations MUST use self-signed certificates. The certificate's
public key is not used for AAFP identity verification; agent identity
is verified at the application layer (see RFC-0003).

Implementations MUST NOT require CA-signed certificates. Implementations
MUST NOT perform certificate chain validation beyond verifying the
self-signed certificate's integrity.

### 2.5 Connection Lifecycle

1. **Connect**: The initiating agent opens a QUIC connection to the
   peer's multiaddr. TLS negotiation occurs, including ALPN and PQ KEX.
2. **Handshake**: After TLS completes, the AAFP application-layer
   handshake occurs on stream 0 (see Section 5).
3. **Established**: The session is authenticated. Agents may open
   additional streams for messaging.
4. **Close**: Either agent may close the connection. The closing agent
   SHOULD send a close frame (see Section 4.5) before closing the QUIC
   connection.

## 3. Frame Format

### 3.1 Frame Header

Every AAFP frame begins with a fixed-size header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |    FrameType  |     Flags     |  Reserved     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Stream ID (64)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      Stream ID (continued)                     +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Payload Length (continued, 32 bits)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Extension Length                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Extension Length (continued, 32 bits)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Fields:

| Field | Size | Description |
|-------|------|-------------|
| Version | 8 bits | AAFP protocol version (1 for v1). See RFC-0006. |
| FrameType | 8 bits | Frame type. See Section 4. |
| Flags | 8 bits | Frame-specific flags. See Section 4. |
| Reserved | 8 bits | Reserved for future use. MUST be set to 0 by senders. MUST be ignored by receivers. |
| Stream ID | 64 bits | The stream this frame belongs to. Stream 0 is reserved for the handshake. |
| Payload Length | 64 bits | Length of the payload section in bytes. |
| Extension Length | 64 bits | Length of the extension section in bytes. 0 if no extensions. |

All integer fields are encoded in network byte order (big-endian).

### 3.2 Frame Body

After the header, the frame body consists of two sections:

```
+---------------------------------------------------------------+
|                      Extensions                               |
|                  (Extension Length bytes)                     |
+---------------------------------------------------------------+
|                       Payload                                 |
|                   (Payload Length bytes)                       |
+---------------------------------------------------------------+
```

- **Extensions**: Zero or more extension blocks (see Section 6).
  `Extension Length` is 0 if no extensions are present.
- **Payload**: Frame-type-specific data. For data frames, this is
  application data. For control frames, this is a CBOR-encoded
  control message.

### 3.3 Frame Ordering

Frames within a single QUIC stream are ordered (QUIC guarantees this).
Frames across streams are NOT ordered. Implementations MUST NOT assume
cross-stream ordering.

### 3.4 Maximum Frame Size

The maximum payload size is 1 MiB (1,048,576 bytes). Implementations
MUST reject frames with payloads larger than this limit by sending an
error frame (see RFC-0005) with error code `8001` (frame too large)
and closing the stream.

Larger application messages MUST be fragmented across multiple frames
on the same stream. The `MORE` flag (see Section 4.1) indicates that
more fragments follow.

### 3.5 Backward Compatibility Note

The v0.1 MVP implementation uses a simpler frame format:
`[4-byte length][payload]`. This format is NOT compatible with the v1
frame format specified above. The v0.1 format is a pre-RFC
implementation artifact and is superseded by this specification.

Implementations conforming to RFC-0002 MUST use the frame format
specified in Section 3.1.

## 4. Frame Types

### 4.1 DATA Frame (0x01)

```
FrameType = 0x01
Payload:  Application data (opaque bytes)
```

Flags:
- `0x01` (MORE): More fragments follow on this stream. The receiver
  MUST buffer fragments until a DATA frame without the MORE flag is
  received, then deliver the assembled message.
- `0x02` (COMPRESSED): The payload is compressed. The compression
  algorithm is negotiated via extensions (see RFC-0006). If compression
  was not negotiated, the receiver MUST return error `8002`
  (unexpected compression).

DATA frames carry application-layer messages. The interpretation of
the payload is determined by the application protocol running on the
stream.

### 4.2 HANDSHAKE Frame (0x02)

```
FrameType = 0x02
Payload:  CBOR-encoded handshake message (see Section 5)
```

The HANDSHAKE frame is used only on stream 0 during connection
establishment. It MUST NOT be sent on other streams. Receivers MUST
return error `8003` (handshake on non-zero stream) if a HANDSHAKE
frame is received on a stream other than 0.

### 4.3 RPC_REQUEST Frame (0x03)

```
FrameType = 0x03
Payload:  CBOR-encoded RpcRequest
```

The `RpcRequest` CBOR structure:

```cbor
{
    "id": uint,          // Correlation ID (unique per connection)
    "method": tstr,      // Method name
    "params": bstr,      // Method parameters (opaque bytes)
}
```

### 4.4 RPC_RESPONSE Frame (0x04)

```
FrameType = 0x04
Payload:  CBOR-encoded RpcResponse
```

The `RpcResponse` CBOR structure:

```cbor
{
    "id": uint,           // Matches the request ID
    "result": bstr / null,  // Result data (null if error)
    "error": {
        "code": uint,     // Protocol error code (see RFC-0005)
        "message": tstr,  // Human-readable error message
        "data": bstr / null,  // Optional structured error data
    } / null,
}
```

### 4.5 CLOSE Frame (0x05)

```
FrameType = 0x05
Payload:  CBOR-encoded CloseMessage
```

The `CloseMessage` CBOR structure:

```cbor
{
    "code": uint,       // Close reason code (see RFC-0005)
    "message": tstr,    // Human-readable close reason
}
```

A CLOSE frame indicates that the sender is closing the connection.
After sending a CLOSE frame, the sender MUST NOT send additional
frames. The receiver SHOULD send a CLOSE frame in response and then
close the QUIC connection.

### 4.6 ERROR Frame (0x06)

```
FrameType = 0x06
Payload:  CBOR-encoded ErrorMessage
```

The `ErrorMessage` CBOR structure:

```cbor
{
    "code": uint,        // Protocol error code (see RFC-0005)
    "message": tstr,     // Human-readable error message
    "data": bstr / null, // Optional structured error data
    "fatal": bool,       // If true, the connection must be closed
}
```

If `fatal` is true, the receiver MUST close the connection after
receiving the error frame. If `fatal` is false, the error is
non-fatal and the connection may continue.

### 4.7 PING Frame (0x07)

```
FrameType = 0x07
Payload:  Empty (0 bytes)
```

A PING frame is a keepalive probe. The receiver MUST respond with a
PONG frame on the same stream.

### 4.8 PONG Frame (0x08)

```
FrameType = 0x08
Payload:  Empty (0 bytes)
```

A PONG frame is the response to a PING frame.

### 4.9 Reserved Frame Types

Frame types 0x00 and 0x09–0xFF are reserved for future use.
Implementations receiving an unknown frame type MUST:

1. If the frame's `Flags` field has the critical bit (0x80) set,
   return error `8004` (unknown critical frame type) and close the
   connection.
2. If the critical bit is not set, skip the frame and continue
   processing.

The critical bit mechanism allows new frame types to be introduced
without breaking existing implementations. See RFC-0006 for the
extension registration process.

## 5. Handshake

### 5.1 Overview

The AAFP handshake occurs on stream 0 after the TLS handshake
completes. It authenticates the agents to each other using ML-DSA-65
signatures and establishes the session.

### 5.2 Handshake Messages

The handshake consists of three messages, exchanged as HANDSHAKE
frames on stream 0:

```
Client                                          Server
  |                                               |
  |  HANDSHAKE (ClientHello)                      |
  |---------------------------------------------->|
  |                                               |
  |                  HANDSHAKE (ServerHello)      |
  |<----------------------------------------------|
  |                                               |
  |  HANDSHAKE (ClientFinished)                   |
  |---------------------------------------------->|
  |                                               |
  |             Session Established                |
```

### 5.3 ClientHello

```cbor
{
    "protocol_version": uint,        // AAFP version (1)
    "agent_id": bstr,                // 32-byte AgentId
    "public_key": bstr,              // ML-DSA-65 public key (1952 bytes)
    "nonce": bstr,                   // 32-byte random nonce
    "capabilities": [ ... ],         // CapabilityDescriptor array
    "extensions": [ ... ],           // Supported extensions (optional)
    "signature": bstr,               // ML-DSA-65 signature over the
                                     // CBOR encoding of this map
                                     // (excluding "signature" field)
}
```

### 5.4 ServerHello

```cbor
{
    "protocol_version": uint,        // AAFP version (1)
    "agent_id": bstr,                // 32-byte AgentId
    "public_key": bstr,              // ML-DSA-65 public key (1952 bytes)
    "nonce": bstr,                   // 32-byte random nonce
    "capabilities": [ ... ],         // CapabilityDescriptor array
    "extensions": [ ... ],           // Supported extensions (optional)
    "session_id": bstr,              // Cryptographically unique session
                                     // identifier (see RFC-0003)
    "signature": bstr,               // ML-DSA-65 signature over the
                                     // CBOR encoding of this map
                                     // (excluding "signature" field)
}
```

### 5.5 ClientFinished

```cbor
{
    "session_id": bstr,              // Echoed from ServerHello
    "signature": bstr,               // ML-DSA-65 signature over
                                     // (ClientHello || ServerHello)
                                     // transcript
}
```

### 5.6 Session ID

The Session ID is a cryptographically unique identifier bound to the
authenticated session. It MUST satisfy the following properties:

1. **Uniqueness**: No two sessions between any pair of agents share
   the same Session ID.
2. **Unpredictability**: An adversary cannot predict the Session ID
   before the handshake completes.
3. **Binding**: The Session ID is cryptographically bound to both
   agents' identities and the handshake transcript.

The derivation method is an implementation detail. A RECOMMENDED
approach is `HKDF-SHA256(handshake_transcript, info="aafp-session-id")`,
but implementations MAY use any method satisfying the above properties.

### 5.7 Handshake Error Handling

If the handshake fails, the detecting side MUST send an ERROR frame
with an appropriate error code (see RFC-0005) and close the connection.

Handshake error codes:
- `2001`: Invalid signature
- `2002`: Expired or revoked identity
- `2003`: Unknown agent
- `2004`: Protocol version mismatch
- `2005`: Unsupported extensions

## 6. Extensions

### 6.1 Extension Encoding

Extensions are carried in the `Extensions` section of the frame body.
Each extension is encoded as:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Extension Type        |    Critical   |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Extension Data Length                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Extension Data Length (continued)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Extension Data ...                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| Extension Type | 16 bits | Extension type identifier. See RFC-0006 for registry. |
| Critical | 8 bits | If 0x01, the extension is critical. Unknown critical extensions MUST cause the frame to be rejected. If 0x00, unknown extensions MUST be skipped. |
| Reserved | 8 bits | MUST be 0. MUST be ignored by receivers. |
| Extension Data Length | 32 bits | Length of extension data in bytes. |
| Extension Data | Variable | Extension-type-specific data. |

### 6.2 Extension Ordering

Extensions MAY appear in any order. Implementations MUST NOT assume
a specific ordering. If two extensions of the same type appear in a
single frame, the first one MUST be used and subsequent ones MUST be
ignored (or rejected if critical).

### 6.3 Negotiated vs Optional Extensions

- **Optional extensions** (Critical = 0): The sender includes the
  extension; the receiver may ignore it. No negotiation required.
- **Negotiated extensions**: The sender proposes the extension in
  the handshake; the receiver accepts or rejects in its handshake
  response. Once negotiated, the extension is active for the session.
- **Mandatory extensions** (Critical = 1): The sender requires the
  receiver to understand the extension. If the receiver does not
  recognize it, the frame MUST be rejected.

See RFC-0006 for the extension negotiation protocol and registry.

## 7. Stream Multiplexing

### 7.1 Stream IDs

Stream IDs are 64-bit unsigned integers. The low bit indicates
initiator:

- Even stream IDs: Client-initiated
- Odd stream IDs: Server-initiated

Stream 0 is reserved for the handshake. Streams 1 and 2 are reserved
for future protocol use. Application streams start at stream ID 4
(client-initiated) or 5 (server-initiated).

### 7.2 Stream Lifecycle

1. **Open**: An agent opens a QUIC bidirectional stream and sends
   one or more DATA frames on it.
2. **Active**: Both agents may send and receive frames on the stream.
3. **Half-close**: An agent finishes sending by closing the send
   side of the QUIC stream. The receive side remains open.
4. **Closed**: Both sides are closed. The stream ID may not be reused.

### 7.3 Flow Control

QUIC provides per-stream and per-connection flow control. AAFP does
not add additional flow control. Implementations SHOULD rely on QUIC's
built-in flow control.

## 8. CBOR Encoding Rules

### 8.1 Canonical CBOR

All AAFP CBOR structures MUST be encoded using deterministic CBOR
(RFC 7049 Section 3.9) with the following rules:

1. Map keys are sorted by canonical byte ordering of their CBOR
   encoding (shortest encoding first, then lexicographic).
2. Integers use the shortest encoding.
3. Floating-point values use the shortest encoding that preserves
   precision.
4. Indefinite-length arrays and maps MUST NOT be used.
5. Text strings use definite-length UTF-8 encoding.

### 8.2 Why Canonical Encoding

Canonical CBOR ensures that the same logical value produces the same
byte sequence across implementations. This is required for:

- **Signature verification**: Signatures are computed over CBOR-encoded
  bytes. Non-canonical encoding would cause signature verification
  failures across implementations.
- **Hashing**: AgentRecords may be hashed for deduplication. Canonical
  encoding ensures consistent hashes.
- **Caching**: Canonical encoding enables byte-level cache comparison.

### 8.3 Schema Evolution

CBOR schemas in AAFP are designed for forward and backward
compatibility:

- New fields MAY be added to maps. Implementations MUST ignore unknown
  fields unless the field is marked critical (see RFC-0006).
- Fields MUST NOT be removed. Deprecated fields MUST be retained with
  their original semantics.
- Field types MUST NOT change. A field that is `uint` in v1 MUST
  remain `uint` in all future versions.

## 9. Security Considerations

### 9.1 Frame Header Integrity

The frame header is not encrypted by AAFP. It is protected by QUIC's
packet protection, which encrypts all QUIC payload including AAFP
frames. Implementations MUST NOT rely on AAFP-level encryption; QUIC
provides transport encryption.

### 9.2 Extension Security

Extensions may carry security-sensitive data (e.g., authorization
tokens). Implementations MUST process extensions before the payload
if the extension is critical. Non-critical extensions MAY be processed
after the payload.

### 9.3 DoS Mitigation

- The maximum frame size (1 MiB) limits memory consumption per frame.
- Implementations SHOULD enforce a maximum number of concurrent streams
  per connection.
- Implementations SHOULD enforce a rate limit on PING frames.
- Implementations SHOULD close connections that send malformed frames
  at a high rate.

## 10. IANA Considerations

This RFC defines the following registries (managed per RFC-0006):

- **AAFP Frame Types**: Values 0x00–0xFF
- **AAFP Extension Types**: Values 0x0000–0xFFFF
- **AAFP ALPN Identifiers**: e.g., `aafp/1`

## 11. References

- RFC 2119: Key words for use in RFCs to indicate requirement levels
- RFC 7049: Concise Binary Object Representation (CBOR)
- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- FIPS 204: Module-Lattice-Based Digital Signature (ML-DSA)
