# RFC-0002: AAFP Transport & Framing

```
Status:         Freeze Candidate (Revision 5)
Number:         0002
Title:          Transport, Framing, Stream Multiplexing, and Wire Format
Author:         AAFP Project
Created:        2025-06-25
Revised:        2025-01-15 (Revision 4: SA-0002 clarification — empty
                CBOR map key-type interpretation)
                2025-01-16 (Revision 5: no content changes, version bump
                for consistency with RFC-0003)
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
2. **Channel Binding**: After TLS completes, both sides compute the
   TLS channel binding value (see Section 5.6).
3. **Handshake**: The AAFP application-layer handshake occurs on
   stream 0 (see Section 5). The channel binding value is included
   in the handshake transcript hash.
4. **Established**: The session is authenticated. Agents may open
   additional streams for messaging.
5. **Close**: Either agent may close the connection. The closing agent
   SHOULD send a close frame (see Section 4.5) before closing the QUIC
   connection.

After TLS handshake completion and before sending the ClientHello,
both sides MUST compute the TLS channel binding value:

```
tls_binding = TLS-Exporter("EXPORTER-AAFP-Channel-Binding", "", 32)
```

The TLS exporter is defined in RFC 8446 Section 7.5. It produces a
32-byte value unique to the TLS session. Including this value in the
AAFP transcript hash (Section 5.6) binds the AAFP session to the
specific TLS channel, preventing relay attacks. See RFC 9266 for
the standard TLS 1.3 channel binding mechanism.

If the TLS exporter is not available (e.g., the TLS implementation
does not support RFC 8446 exporters), the implementation MUST NOT
proceed with the handshake. The connection MUST be closed with
error code 2006 (HANDSHAKE_FAILED).

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
ERROR frame (see RFC-0005) with error code `8001` (FRAME_TOO_LARGE)
and closing the stream. The ERROR frame's fatal flag SHOULD be false
(non-fatal), allowing the connection to continue for other streams.
If the peer repeatedly sends oversized frames, the implementation MAY
set the fatal flag to true and close the connection.

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

The `RpcRequest` CBOR structure (integer keys, per Section 8):

```cbor
RpcRequest = {
    1: uint,       // "id": Correlation ID (unique per connection)
    2: tstr,       // "method": Method name
    3: any,        // "params": Method parameters (CBOR any type)
                   // Structure depends on the method. See individual
                   // method definitions (e.g., RFC-0004 Section 3.3).
                   // For methods with no parameters, use null.
}
```

### 4.4 RPC_RESPONSE Frame (0x04)

```
FrameType = 0x04
Payload:  CBOR-encoded RpcResponse
```

The `RpcResponse` CBOR structure (integer keys, per Section 8):

```cbor
RpcResponse = {
    1: uint,                    // "id": Matches the request ID
    2: any / null,              // "result": Result data (null if error)
                                // Structure depends on the method.
    3: {                        // "error": Error object (null if success)
        1: uint,                //   "code": Error code (see RFC-0005)
        2: tstr,                //   "message": Human-readable message
        3: bstr / null,         //   "data": Optional structured data
    } / null,
}
```

### 4.5 CLOSE Frame (0x05)

```
FrameType = 0x05
Payload:  CBOR-encoded CloseMessage
```

The `CloseMessage` CBOR structure (integer keys, per Section 8):

```cbor
CloseMessage = {
    1: uint,       // "code": Close reason code (see RFC-0005)
    2: tstr,       // "message": Human-readable close reason
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

The `ErrorMessage` CBOR structure (integer keys, per Section 8):

```cbor
ErrorMessage = {
    1: uint,            // "code": Protocol error code (see RFC-0005)
    2: tstr,            // "message": Human-readable error message
    3: bstr / null,     // "data": Optional structured error data
    4: bool,            // "fatal": If true, the connection must be closed
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

A PING frame is an application-layer keepalive probe. The receiver
MUST respond with a PONG frame on the same stream.

PING frames MAY be sent on any open stream, including stream 0
(the handshake stream, which remains open after the handshake
completes). Sending PING on stream 0 is RECOMMENDED for
connection-level keepalive, as it does not require opening a new
stream.

Note: QUIC provides its own transport-level keepalive mechanism
(via idle timeout and PING frames at the QUIC layer). AAFP PING/
PONG frames are for application-layer liveness checks and are
distinct from QUIC's keepalive. Implementations MAY use either or
both mechanisms.

### 4.8 PONG Frame (0x08)

```
FrameType = 0x08
Payload:  Empty (0 bytes)
```

A PONG frame is the response to a PING frame. It MUST be sent on
the same stream as the PING frame.

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

Stream 0 remains open for the lifetime of the connection after the
handshake completes. It is used for connection-level frames:
- PING / PONG frames (Section 4.7)
- GOAWAY frames (Section 4.8)
- ERROR frames with fatal severity (RFC-0005 Section 4.4)

Stream 0 MUST NOT be used for DATA frames or RPC frames after the
handshake. Application data flows on streams >= 4 (client-initiated)
or >= 5 (server-initiated).

### 5.3 ClientHello

```cbor
ClientHello = {
    1: uint,       // "protocol_version": AAFP version (1)
    2: bstr,       // "agent_id": 32-byte AgentId
    3: bstr,       // "public_key": ML-DSA-65 public key (1952 bytes)
    4: bstr,       // "nonce": 32-byte random nonce
    5: [ *CapabilityDescriptor ],  // "capabilities"
    6: [ *ExtensionEntry ],        // "extensions" (see Section 6.4)
    7: bstr,       // "signature": ML-DSA-65 signature (see Section 5.6)
    8: uint,       // "expires_at": Unix timestamp (seconds)
    9: bstr / null, // "receiver_mac": Optional DoS pre-verification
                    //   MAC (see Section 5.8). Null if DoS profile
                    //   is not active.
    10: uint,      // "key_algorithm": Signature algorithm (see
                   //   RFC-0003 Section 2.3). 1 = ML-DSA-65.
}
```

### 5.4 ServerHello

```cbor
ServerHello = {
    1: uint,       // "protocol_version": AAFP version (1)
    2: bstr,       // "agent_id": 32-byte AgentId
    3: bstr,       // "public_key": ML-DSA-65 public key (1952 bytes)
    4: bstr,       // "nonce": 32-byte random nonce
    5: [ *CapabilityDescriptor ],  // "capabilities"
    6: [ *ExtensionEntry ],        // "extensions" (accepted subset,
                                   //   see Section 6.4)
    7: bstr,       // "session_id": Session identifier (see Section 5.7)
    8: bstr,       // "signature": ML-DSA-65 signature (see Section 5.6)
    9: uint,       // "expires_at": Unix timestamp (seconds)
    10: uint,      // "key_algorithm": Signature algorithm
}
```

### 5.5 ClientFinished

```cbor
ClientFinished = {
    1: bstr,       // "session_id": Echoed from ServerHello
    2: bstr,       // "signature": ML-DSA-65 signature over
                   //   transcript hash (see Section 5.6)
}
```

### 5.6 Transcript Hash and Signature Computation

The handshake transcript hash is a running SHA-256 hash over the
canonical CBOR encodings of handshake messages, prefixed with the
TLS channel binding value (see Section 2.5). Every handshake signature
is computed over the transcript hash **after** the current message's
CBOR has been folded into the hash. This is the single source of truth
for signature inputs — there are no separate concatenation formulas.

#### Signature Input Encoding

When a signature input specification says
`canonical_CBOR(Message_without_field_X)`, this means:

1. Construct a NEW CBOR map containing exactly the fields of the
   message EXCLUDING the specified field(s).
2. Encode this map using canonical CBOR (Section 8.1).
3. The resulting byte sequence is the signature input component.

The excluded fields are omitted entirely — they are not present in
the map, not encoded as null, and not encoded with zero-length
values. The map length reflects only the included fields.

For example, `canonical_CBOR(ClientHello_without_signature_and_receiver_mac)`
produces a CBOR map with 8 entries (keys 1, 2, 3, 4, 5, 6, 8, 10),
encoded in canonical form. Keys 7 (signature) and 9 (receiver_mac)
are absent from the map.

#### Transcript Hash and Signature Procedure

All AAFP signatures use domain separators (see RFC-0003 Section 3.5)
to prevent cross-protocol signature reuse. The domain separator
for handshake signatures is `"aafp-v1-handshake"`.

The signature is over the 32-byte transcript hash (prefixed with the
domain separator), not raw message concatenation. This is important
for ML-DSA-65 which has a maximum message size.

**Step 1: Initialize**

After TLS handshake completion, both sides compute the TLS channel
binding and initialize the transcript hash:
```
tls_binding = TLS-Exporter("EXPORTER-AAFP-Channel-Binding", "", 32)
h = SHA-256(tls_binding)
```

**Step 2: ClientHello Phase**

Sender (client):
1. Construct ClientHello without signature (key 7) and receiver_mac
   (key 9).
2. Compute `CH_CBOR = canonical_CBOR(ClientHello_without_sig_and_mac)`.
3. Update transcript: `h = SHA-256(h || CH_CBOR)`.
4. Compute signature:
   ```
   ClientHello.signature = ML-DSA-65.Sign(
       secret_key,
       "aafp-v1-handshake" || h)
   ```
5. Insert signature into ClientHello (key 7).
6. Send ClientHello.

Receiver (server):
1. Receive ClientHello.
2. Extract `CH_CBOR = canonical_CBOR(ClientHello_without_sig_and_mac)`.
3. Update transcript: `h = SHA-256(h || CH_CBOR)`.
4. Verify `ClientHello.signature` against `h` using the public key
   in ClientHello (key 3).

**Step 3: ServerHello Phase**

Sender (server):
1. Construct ServerHello without signature (key 8).
2. Compute `SH_CBOR = canonical_CBOR(ServerHello_without_sig)`.
3. Update transcript: `h = SHA-256(h || SH_CBOR)`.
4. Compute signature:
   ```
   ServerHello.signature = ML-DSA-65.Sign(
       secret_key,
       "aafp-v1-handshake" || h)
   ```
5. Insert signature into ServerHello (key 8).
6. Send ServerHello.

Receiver (client):
1. Receive ServerHello.
2. Extract `SH_CBOR = canonical_CBOR(ServerHello_without_sig)`.
3. Update transcript: `h = SHA-256(h || SH_CBOR)`.
4. Verify `ServerHello.signature` against `h` using the public key
   in ServerHello (key 3).

**Step 4: ClientFinished Phase**

Sender (client):
1. Construct ClientFinished without signature (key 2).
2. Compute `CF_CBOR = canonical_CBOR(ClientFinished_without_sig)`.
3. Update transcript: `h = SHA-256(h || CF_CBOR)`.
4. Compute signature:
   ```
   ClientFinished.signature = ML-DSA-65.Sign(
       secret_key,
       "aafp-v1-handshake" || h)
   ```
5. Insert signature into ClientFinished (key 2).
6. Send ClientFinished.

Receiver (server):
1. Receive ClientFinished.
2. Extract `CF_CBOR = canonical_CBOR(ClientFinished_without_sig)`.
3. Update transcript: `h = SHA-256(h || CF_CBOR)`.
4. Verify `ClientFinished.signature` against `h`.

**Step 5: Session Established**

The final transcript hash `h` (after Step 4) is used for Session ID
derivation (Section 5.7).

#### Key Principle

The signature is ALWAYS computed over `"aafp-v1-handshake" || h` where
`h` is the transcript hash AFTER the current message's CBOR has been
folded in. The receiver ALWAYS updates the transcript hash BEFORE
verifying the signature. This ensures both sides have the same `h`
value at verification time.

### 5.7 Session ID

The Session ID is a cryptographically unique identifier bound to the
authenticated session. It MUST satisfy the following properties:

1. **Uniqueness**: No two sessions between any pair of agents share
   the same Session ID.
2. **Unpredictability**: An adversary cannot predict the Session ID
   before the handshake completes.
3. **Binding**: The Session ID is cryptographically bound to both
   agents' identities and the handshake transcript.

The Session ID MUST be derived using HKDF-SHA256 over the transcript
hash after the ClientHello phase (Section 5.6, Step 2) and both
agents' nonces:

```
prk = HKDF-Extract(
    salt = client_nonce || server_nonce,
    IKM  = h_after_clienthello)
session_id = HKDF-Expand(prk, info = "aafp-session-id-v1", L = 32)
```

Where:
- `h_after_clienthello` is the transcript hash after Step 2 of
  Section 5.6 (after ClientHello CBOR is folded in, before ServerHello).
- `client_nonce` is the 32-byte nonce from ClientHello (key 4).
- `server_nonce` is the 32-byte nonce from ServerHello (key 4).
- Nonce concatenation order: `client_nonce` first, then `server_nonce`
  (64 bytes total).
- HKDF uses SHA-256 as the hash function.
- The `info` string `"aafp-session-id-v1"` is encoded as raw UTF-8
  bytes (no null terminator, no length prefix, no CBOR encoding).

The server computes the Session ID before constructing ServerHello
(it knows `h_after_clienthello` from receiving ClientHello, and it
knows both nonces). The server includes the Session ID in ServerHello
(key 7).

The client computes the Session ID after receiving ServerHello (it
needs the server's nonce). The client MUST verify that the Session ID
in ServerHello (key 7) matches its independently derived value. If
they differ, the client MUST send an ERROR frame with code 2006
(HANDSHAKE_FAILED) and close the connection.

The Session ID is bound to:
- The TLS channel binding (via `h_after_clienthello`)
- The ClientHello content (agent_id, public_key, capabilities,
  extensions)
- Both agents' nonces

It is NOT directly bound to ServerHello content, but the ServerHello
signature covers the full transcript (which includes ServerHello),
and the ClientFinished signature covers the full transcript including
ClientFinished. This provides end-to-end binding.

This derivation is normative (MUST). All implementations MUST use
this exact derivation to ensure session ID interoperability for
future session resumption features.

### 5.8 DoS Mitigation Profile (Optional)

Deployments facing DoS threats (e.g., Internet-facing bootstrap nodes,
public network deployments) SHOULD implement the pre-verification
mechanism described in this section. Private network deployments or
authenticated environments MAY omit it.

The DoS mitigation profile provides cheap HMAC verification (~1μs)
before expensive ML-DSA-65 signature verification (~1ms), reducing
the cost of rejecting invalid ClientHello messages by ~1000x.

This profile is OPTIONAL. Implementations conforming to AAFP v1 are
not required to implement it. However, Internet-facing deployments
SHOULD enable it.

#### Mechanism

When the DoS mitigation profile is active, the ClientHello includes
field 9 (receiver_mac) containing a receiver MAC:

```
mac_key = HKDF-SHA256(
    input = receiver_agent_id,
    info  = "aafp-v1-dos-mac-key",
    L     = 32)
receiver_mac = HMAC-SHA256(
    key  = mac_key,
    data = canonical_CBOR(ClientHello_without_signature_and_receiver_mac))
```

The `canonical_CBOR(ClientHello_without_signature_and_receiver_mac)`
used for the receiver_mac computation is the same byte sequence as
`CH_CBOR` used in the transcript hash (Section 5.6, Step 2). This is
the canonical CBOR encoding of a map with keys 1, 2, 3, 4, 5, 6, 8,
10 (excluding keys 7 and 9), per the signature input encoding rules
in Section 5.6.

The server verifies the receiver_mac (a cheap HMAC operation, ~1μs)
before verifying the ML-DSA-65 signature (~1ms). If the MAC is
invalid, the server rejects the ClientHello with error code 2009
(RECEIVER_MAC_INVALID) without performing signature verification.

The receiver_mac proves that the sender knows the receiver's
AgentId. It does NOT authenticate the sender (the sender's identity
is verified by the ML-DSA-65 signature). The purpose of
receiver_mac is to allow the server to reject messages from
attackers who do not know the server's AgentId, without performing
expensive signature verification.

#### Negotiation

The DoS mitigation profile is negotiated via a handshake extension
(type 0x0001, "dos-mitigation"). The client includes this extension
in ClientHello.extensions if it supports the profile. The server
includes it in ServerHello.extensions if it requires the profile.

If the server requires the profile but the client did not propose
it, the server MUST send an ERROR frame with code 2005
(UNSUPPORTED_EXTENSIONS) and close the connection.

If neither side requires the profile, ClientHello field 9
(receiver_mac) MAY be null. If field 9 is null, the server proceeds
directly to signature verification.

#### Cookie Mechanism (Future)

A cookie-based mechanism (similar to WireGuard's mac2) for
proof-of-IP under load is deferred to a future RFC. The current
profile provides receiver-identity verification but not
source-address verification.

### 5.9 Handshake Error Handling

If the handshake fails, the detecting side MUST send an ERROR frame
with an appropriate error code (see RFC-0005) and close the connection.

Handshake error codes:
- `2001`: Invalid signature (ML-DSA-65 signature verification failed)
- `2002`: Expired or revoked identity (`expires_at` is in the past)
- `2003`: Unknown agent
- `2004`: Protocol version mismatch
- `2005`: Unsupported extensions
- `2006`: Handshake failed (including TLS exporter unavailable)
- `2007`: Invalid AgentId (AgentId does not match SHA-256(public_key))
- `2009`: Receiver MAC invalid (DoS pre-verification failed)

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
| Extension Data Length | 32 bits | Length of extension data in bytes. Big-endian unsigned integer. |
| Extension Data | Variable | Extension-type-specific data. |

Multiple extensions are concatenated directly within the Extensions
section of the frame body. Each extension is self-delimiting via its
Extension Data Length field. There is no additional framing between
extensions. The total size of all extensions MUST equal the Extension
Length field in the frame header.

Example with two extensions:
```
[Ext1.Type:2][Ext1.Critical:1][Ext1.Reserved:1][Ext1.DataLen:4][Ext1.Data:N]
[Ext2.Type:2][Ext2.Critical:1][Ext2.Reserved:1][Ext2.DataLen:4][Ext2.Data:M]
```

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

See Section 6.4 for the handshake extension negotiation protocol.
See RFC-0006 for the extension type registry.

### 6.4 Handshake Extension Negotiation

Extensions are negotiated during the handshake. The ClientHello
includes a list of proposed extensions; the ServerHello includes a
list of accepted extensions (a subset of the client's proposals).

#### Extension Entry Format

Each extension entry in the handshake is a CBOR map with integer
keys (per Section 8):

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

The ClientHello.extensions field (key 6) is a CBOR array of
ExtensionEntry maps, listing all extensions the client proposes.

The ServerHello.extensions field (key 6) is a CBOR array of
ExtensionEntry maps, listing the extensions the server accepts.
This MUST be a subset of the extensions proposed by the client.
The server MUST NOT include extensions that the client did not
propose.

#### Parameter Negotiation

When a client proposes an extension, the extension data (key 2)
contains the client's proposed parameters. When the server accepts
the extension, the server's extension data (key 2) contains the
server's selected parameters, which MAY differ from the client's
proposal.

The semantics of parameter negotiation are extension-type-specific.
The extension specification MUST define:
- What parameters the client proposes
- What parameters the server may select
- Whether the server must select a subset of the client's proposal
  or may choose independently

Example (hypothetical max-frame-size extension, type 0x0003):
- Client proposes: data = CBOR uint 1048576 (1 MiB)
- Server selects: data = CBOR uint 262144 (256 KiB)
- Both sides use 256 KiB as the maximum frame size for the session.

#### Negotiation Rules

1. The client proposes extensions by including ExtensionEntry maps
   in ClientHello.extensions.
2. The server accepts a subset by including ExtensionEntry maps in
   ServerHello.extensions. The server MAY include extension data
   that differs from the client's proposal (e.g., selecting
   parameters).
3. Extensions not included in ServerHello.extensions are NOT active
   for the session.
4. If the client proposed an extension with `critical = true` (key 3)
   and the server did not accept it (did not include it in
   ServerHello.extensions), the server MUST send an ERROR frame with
   code 2005 (UNSUPPORTED_EXTENSIONS) and close the connection. If
   `critical = false`, the server MAY silently drop the extension.
5. Using a non-negotiated extension in a subsequent frame (after the
   handshake) is a protocol error. The receiver MUST send an ERROR
   frame with code 8007 (INVALID_FLAGS) and close the connection.

#### Relationship to Frame Extensions

Frame-level extensions (Section 6.1) use a binary encoding in the
frame body's Extension section. Handshake-level extensions use CBOR
ExtensionEntry maps in the handshake messages. These are distinct
mechanisms:

- Handshake extensions negotiate session-wide features.
- Frame extensions carry per-frame metadata.

A handshake extension MAY correspond to a frame extension type. For
example, a compression extension negotiated in the handshake would
enable the COMPRESSED flag in DATA frames.

#### Defined Handshake Extensions

| Type | Name | Description |
|------|------|-------------|
| 0x0001 | dos-mitigation | DoS pre-verification profile (Section 5.8) |
| 0x0002–0x3FFF | Reserved | Standards-track (assigned via RFC) |

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

All AAFP CBOR structures MUST be encoded using length-first core
deterministic encoding requirements (RFC 8949 Section 4.2.3) with
the following rules:

1. Map keys are sorted by the length-first canonical byte ordering
   of their CBOR encoding, as specified in RFC 8949 Section 4.2.3.
   This means:
   - Keys with shorter CBOR encodings come before keys with longer
     encodings.
   - Within the same encoding length, keys are sorted bytewise
     lexicographically.
   
   For integer keys (CBOR major type 0 or 1):
   - Integers 0-23: encoded as 1 byte. Sorted numerically.
   - Integers 24-255: encoded as 2 bytes (0x18 prefix + value).
     Sorted by value, which is the same as bytewise order.
   - All 1-byte keys sort before all 2-byte keys.
   
   Example: keys 1, 2, 5, 10 sort as 1, 2, 5, 10 (all 1-byte).
   Example: keys 1, 24, 100 sort as 1 (1-byte), then 24, 100 (2-byte).
2. Integers use the shortest encoding.
3. Floating-point values use the shortest encoding that preserves
   precision. (Note: AAFP v1 does not use floating-point values in
   any defined structure. This rule is included for completeness and
   future compatibility.)
4. Indefinite-length arrays and maps MUST NOT be used.
5. Text strings use definite-length UTF-8 encoding.
6. All CBOR maps use integer keys (not string keys). See Section 8.4
   for the normative key mapping table.

**Exception**: The CapabilityDescriptor metadata map (RFC-0003
Section 4.5) uses text string keys (CBOR major type 3), not integer
keys. This is because metadata keys are application-defined and
cannot be pre-assigned integer values. String keys in the metadata
map are sorted by length-first canonical byte ordering of their
UTF-8 encoding, consistent with RFC 8949 Section 4.2.3. All other
AAFP CBOR maps use integer keys.

**Empty map key type (Revision 4 clarification)**: When a CBOR map
is empty (encoded as `a0`, major type 5, 0 entries), the CBOR
encoding does not distinguish between int-keyed and string-keyed
maps — both produce the byte `0xa0`. For AAFP fields with a
schema-defined key type, the key type MUST be determined from the
enclosing schema, not from the CBOR major type of the encoded data.
Specifically:

- A field defined as `map<uint, T>` (int-keyed) MUST be interpreted
  as an integer-keyed map, even when empty.
- A field defined as `map<tstr, T>` (string-keyed, e.g.,
  CapabilityDescriptor metadata) MUST be interpreted as a
  string-keyed map, even when empty.

This rule prevents decoders from rejecting valid empty maps due to
ambiguous CBOR major type interpretation. See RFC-0003 §4.5 for the
specific application to CapabilityDescriptor metadata.

Note: RFC 8949 obsoletes RFC 7049. The length-first deterministic
encoding in RFC 8949 Section 4.2.3 is compatible with the canonical
CBOR rules in RFC 7049 Section 3.9.

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

### 8.4 Integer Key Mapping Table

All AAFP CBOR structures use integer keys for compact encoding and
deterministic canonical ordering. The following table maps integer
keys to field names for all structures defined in this RFC:

| Structure | Key | Field Name |
|-----------|-----|------------|
| RpcRequest | 1 | id |
| RpcRequest | 2 | method |
| RpcRequest | 3 | params |
| RpcResponse | 1 | id |
| RpcResponse | 2 | result |
| RpcResponse | 3 | error |
| RpcResponse.error | 1 | code |
| RpcResponse.error | 2 | message |
| RpcResponse.error | 3 | data |
| CloseMessage | 1 | code |
| CloseMessage | 2 | message |
| ErrorMessage | 1 | code |
| ErrorMessage | 2 | message |
| ErrorMessage | 3 | data |
| ErrorMessage | 4 | fatal |
| ClientHello | 1 | protocol_version |
| ClientHello | 2 | agent_id |
| ClientHello | 3 | public_key |
| ClientHello | 4 | nonce |
| ClientHello | 5 | capabilities |
| ClientHello | 6 | extensions |
| ClientHello | 7 | signature |
| ClientHello | 8 | expires_at |
| ClientHello | 9 | receiver_mac |
| ClientHello | 10 | key_algorithm |
| ServerHello | 1 | protocol_version |
| ServerHello | 2 | agent_id |
| ServerHello | 3 | public_key |
| ServerHello | 4 | nonce |
| ServerHello | 5 | capabilities |
| ServerHello | 6 | extensions |
| ServerHello | 7 | session_id |
| ServerHello | 8 | signature |
| ServerHello | 9 | expires_at |
| ServerHello | 10 | key_algorithm |
| ClientFinished | 1 | session_id |
| ClientFinished | 2 | signature |
| ExtensionEntry | 1 | type |
| ExtensionEntry | 2 | data |
| ExtensionEntry | 3 | critical |

For structures defined in other RFCs (AgentRecord, CapabilityDescriptor,
UcanToken), see the key mapping in those RFCs.

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
- RFC 8949: Concise Binary Object Representation (CBOR) [obsoletes
  RFC 7049]
- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 9266: Channel Bindings for TLS 1.3
- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- RFC-0001: AAFP Protocol Overview
- RFC-0003: AAFP Identity & Authentication
- RFC-0005: AAFP Error Model
- RFC-0006: AAFP Versioning & Compatibility
