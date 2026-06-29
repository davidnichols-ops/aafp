# RFC-0004: AAFP Discovery

```
Status:         Freeze Candidate (Revision 5)
Number:         0004
Title:          Discovery: Identity, Capability, Service, and Resource
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

This RFC specifies the AAFP discovery system, which enables agents to
find each other in the network. AAFP defines four conceptual discovery
classes. The v1 MVP implements Identity Discovery and Capability
Discovery. Service Discovery and Resource Discovery are named but not
implemented.

### 1.1 Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 2. Discovery Classes

### 2.1 Identity Discovery

**Purpose**: Find an agent's network address (multiaddr) given its
AgentId.

**v1 Implementation**: Bootstrap nodes and peer exchange. When an
agent connects to a bootstrap node, it shares its AgentRecord and
receives records of other known agents.

**Future**: A distributed Kademlia DHT keyed by AgentId, enabling
O(log N) lookup in a large network.

### 2.2 Capability Discovery

**Purpose**: Find agents that advertise a given capability (e.g.,
"inference", "translation").

**v1 Implementation**: In-memory capability-keyed DHT. AgentRecords
are indexed by each capability name in their `capabilities` array.
Lookup returns all records matching the capability name.

**Future**: Semantic capability routing supporting multi-dimensional
queries (cost, latency, trust score, hardware). This is deferred
until usage patterns emerge (see RFC-0001 Section 1.3, Non-Goals).

### 2.3 Service Discovery

**Purpose**: Find long-running services (e.g., a persistent inference
endpoint, a model registry, a tool provider).

**v1 Status**: Not implemented. Named as a concept for future work.

**Future**: Service advertisements with availability status, load
metrics, and health checks. Services differ from agents in that they
are persistent endpoints, not interactive peers.

### 2.4 Resource Discovery

**Purpose**: Find agents with available compute resources (CPU, GPU,
memory, storage, bandwidth).

**v1 Status**: Not implemented. Named as a concept for future work.

**Future**: Resource advertisements with capacity, availability
windows, and pricing. This is closely related to the Resource
Exchange layer (out of scope for v1; see RFC-0001 Section 1.3).

## 3. Bootstrap Discovery

### 3.1 Bootstrap Nodes

A bootstrap node is a well-known agent that provides initial peer
discovery. Bootstrap nodes are configured statically (via command-line
flags, configuration files, or DNS records).

Implementations MUST support configuring multiple bootstrap nodes.
Implementations SHOULD use at least 3 bootstrap nodes from different
administrational domains to mitigate eclipse attacks and bootstrap
node compromise (see Section 8.4).

### 3.2 Bootstrap Protocol

1. The connecting agent opens a QUIC connection to the bootstrap
   node's multiaddr.
2. The AAFP handshake completes (see RFC-0003).
3. The connecting agent sends its AgentRecord to the bootstrap node
   via an RPC request (method: `aafp.discovery.announce`).
4. The bootstrap node responds with a list of known AgentRecords
   (method response).
5. The connecting agent may request additional records by capability
   (method: `aafp.discovery.lookup`, params: capability name).

### 3.3 Bootstrap RPC Methods

RPC params and results use CBOR `any` type with integer keys (per
RFC-0002 Section 4.3–4.4 and Section 8.4). The structure depends
on the method.

#### `aafp.discovery.announce`

```cbor
// Request params (RpcRequest key 3)
{
    1: AgentRecord,    // "record": The agent's AgentRecord
}

// Response result (RpcResponse key 2)
{
    1: [ *AgentRecord ],  // "peers": Known peers (may be empty)
}
```

#### `aafp.discovery.lookup`

```cbor
// Request params (RpcRequest key 3)
{
    1: tstr,          // "capability": Capability name to search for
    2: uint / null,   // "limit": Maximum results (optional, default 5
                      //   for unauthenticated, 10 for authenticated)
}

// Response result (RpcResponse key 2)
{
    1: [ *AgentRecord ],  // "peers": Agents with the requested capability
}
```

### 3.4 Bootstrap Node Requirements

- Bootstrap nodes MUST accept incoming connections.
- Bootstrap nodes MUST store AgentRecords received via `announce`.
- Bootstrap nodes MUST respond to `lookup` requests with matching
  records.
- Bootstrap nodes SHOULD evict expired records.
- Bootstrap nodes SHOULD limit the number of records stored to
  prevent memory exhaustion (RECOMMENDED: 100,000 records).
- Bootstrap nodes MUST rate-limit discovery requests per connection:
  - `announce`: Maximum 1 request per 60 seconds per connection.
  - `lookup`: Maximum 10 requests per 60 seconds per connection.
  - `pex`: Maximum 1 request per 60 seconds per connection.
- Bootstrap nodes MUST verify the requester's AgentRecord signature
  before responding to `lookup` requests. If the requester's
  AgentRecord is invalid or expired, the bootstrap node MUST reject
  the request with error code 4003 (RECORD_INVALID) or 4004
  (RECORD_EXPIRED).
- Bootstrap nodes MAY reject requests from agents that have not
  announced their own AgentRecord.
- Bootstrap nodes MAY rate-limit at the IP level for connections
  that exceed per-connection limits.
- The default `limit` parameter for `lookup` is 5 for
  unauthenticated requests (requests from agents without a valid
  AgentRecord) and 10 for authenticated requests.
- Bootstrap nodes MUST limit lookup responses to 5 AgentRecords for
  unauthenticated requests. Authenticated requests MAY receive up
  to 10 records.
- Implementations SHOULD enforce a maximum number of concurrent
  streams per connection (RECOMMENDED: 100) to prevent resource
  exhaustion.

## 4. Capability DHT

### 4.1 Overview

The capability DHT indexes AgentRecords by capability name. It is the
primary mechanism for Capability Discovery in v1.

### 4.2 v1 Implementation

The v1 capability DHT is an in-memory hash map:

```
capability_name -> Set<AgentRecord>
```

This is suitable for single-node deployments and small networks. It
is NOT a distributed DHT. A distributed Kademlia-style DHT is
deferred to a future RFC.

### 4.3 DHT Operations

#### Put

Stores an AgentRecord indexed by each capability in its
`capabilities` array.

```
put(record: AgentRecord):
    for capability in record.capabilities:
        index[capability.name].insert(record)
```

If a record with the same AgentId already exists, it is replaced.
The new record MUST have a `created_at` timestamp greater than or
equal to the existing record's `created_at`.

#### Get

Returns all AgentRecords matching a capability name.

```
get(capability_name: String) -> Vec<AgentRecord>:
    return index[capability_name]
```

#### Get All

Returns all AgentRecords matching ALL of the specified capabilities
(intersection).

```
get_all(capability_names: &[String]) -> Vec<AgentRecord>:
    results = index[capability_names[0]]
    for name in capability_names[1..]:
        results = results ∩ index[name]
    return results
```

#### Remove

Removes an AgentRecord from the index.

```
remove(agent_id: AgentId):
    for capability in all_capabilities:
        index[capability].remove_where(r => r.agent_id == agent_id)
```

### 4.4 Record Expiry

The DHT SHOULD periodically evict expired records. A record is
expired when `current_time > record.expires_at`. The eviction
interval is implementation-defined (RECOMMENDED: every 60 seconds).

### 4.5 Future: Distributed DHT

A future RFC will specify a distributed Kademlia DHT with:

- AgentId-based node IDs (for routing)
- Capability-name-based key hashing (for storage)
- Replication factor (for redundancy)
- Bucket-based routing tables
- Iterative lookup (for O(log N) lookup time)

The v1 in-memory DHT provides the API surface for this future work.
The `put`, `get`, `get_all`, and `remove` operations will remain
the same; only the implementation changes.

## 5. Regional Discovery

### 5.1 Purpose

Regional discovery groups agents by geographic region to enable
latency-optimized peer selection. When multiple agents have the same
capability, the requesting agent prefers agents in the same or nearby
regions.

### 5.2 Regions

v1 defines five regions:

| Region | Code | Description |
|--------|------|-------------|
| US-East | 0 | Eastern North America |
| US-West | 1 | Western North America |
| Europe | 2 | Europe |
| Asia-Pacific | 3 | Asia and Pacific |
| South-America | 4 | South America |

Future versions MAY add regions. Region codes 5–255 are reserved.

### 5.3 Region Assignment

Agents are assigned to a region based on their configured region
preference. The protocol does not perform automatic geolocation in
v1. Future versions MAY use latency probes or IP geolocation for
automatic region assignment.

### 5.4 Closest-Peer Selection

```
find_closest(local_region: Region, count: uint) -> Vec<AgentRecord>:
    peers = agents_in_region(local_region)
    if peers.len() >= count:
        return peers[0..count]
    // Fall back to other regions
    for region in all_regions_sorted_by_distance(local_region):
        peers.extend(agents_in_region(region))
        if peers.len() >= count:
            return peers[0..count]
    return peers
```

Region distance is defined as a static distance matrix. The distance
between regions in v1 is:

| From \ To | US-East | US-West | Europe | APAC | SA |
|-----------|---------|---------|--------|------|----|
| US-East | 0 | 1 | 2 | 3 | 2 |
| US-West | 1 | 0 | 3 | 2 | 3 |
| Europe | 2 | 3 | 0 | 3 | 4 |
| APAC | 3 | 2 | 3 | 0 | 4 |
| SA | 2 | 3 | 4 | 4 | 0 |

This is a rough approximation. Future versions MAY use measured
latency instead.

## 6. Peer Exchange

### 6.1 Purpose

Peer exchange (PEX) allows connected agents to share known peers,
reducing reliance on bootstrap nodes.

### 6.2 PEX Protocol

PEX is performed via RPC after the handshake completes:

#### `aafp.discovery.pex`

```cbor
// Request params (RpcRequest key 3)
{
    1: [ *bstr ],     // "known_peers": AgentIds the requester already knows
    2: uint / null,   // "limit": Maximum new peers to receive (optional)
}

// Response result (RpcResponse key 2)
{
    1: [ *AgentRecord ],  // "peers": Peers the responder knows that the
                          // requester doesn't
}
```

### 6.3 PEX Behavior

- Agents SHOULD perform PEX with newly connected peers.
- Agents SHOULD NOT send more than 50 records per PEX response.
- Agents SHOULD NOT perform PEX more than once per minute per peer.
- Agents MUST NOT advertise peers whose AgentRecords have expired.
- Agents MAY filter PEX responses by region or capability.

## 7. Discovery and CapabilityDescriptor

### 7.1 Indexing

The capability DHT indexes AgentRecords by the `name` field of each
`CapabilityDescriptor` in the record's `capabilities` array. The
`metadata` field is NOT indexed in v1.

### 7.2 Future: Metadata-Based Filtering

Future versions MAY support filtering by metadata fields (e.g.,
"find inference agents with model=gpt-oss-120b"). This requires
either:

- A secondary index on metadata fields, or
- A semantic routing layer (deferred; see RFC-0001 Non-Goals)

The `CapabilityDescriptor` schema (RFC-0003) provides the extension
point for this future work without requiring wire format changes.

## 8. Security Considerations

### 8.1 Record Authenticity

All AgentRecords stored in the DHT MUST be self-signed (see RFC-0003
Section 3.5). Implementations MUST verify signatures before storing
or returning records. Records with invalid signatures MUST be
rejected.

### 8.2 Record Expiry

Implementations MUST NOT serve expired records. Expired records MUST
be evicted from the DHT. This prevents stale capability
advertisements from persisting in the network.

### 8.3 Sybil Attacks

The capability DHT is vulnerable to Sybil attacks: an attacker
creates many agent identities to dominate a capability. v1 does not
provide Sybil resistance. Future versions MAY introduce:

- Proof-of-work for record creation
- Reputation systems
- Trusted issuer requirements

### 8.4 Eclipse Attacks

A bootstrap node can eclipse an agent by returning only attacker-
controlled peers. Mitigations:

- Use multiple bootstrap nodes from different providers
- Use PEX with multiple peers to cross-check
- Future: DHT routing diversity requirements

#### Bootstrap Node Compromise

If a bootstrap node is compromised:

1. **Eclipse attack**: The bootstrap node can return only attacker-
   controlled peers, isolating the victim from the legitimate network.
2. **Identity enumeration**: The bootstrap node learns the AgentId,
   public key, capabilities, and endpoints of all connecting agents.
3. **DHT poisoning**: The bootstrap node can inject false AgentRecords
   into the DHT (though all records must be validly signed).
4. **Discovery disruption**: The bootstrap node can reject legitimate
   announcements.

Mitigations (normative):
- Implementations MUST support configuring multiple bootstrap nodes.
- Implementations SHOULD use at least 3 bootstrap nodes from different
  administrative domains.
- Implementations SHOULD use PEX (Section 5) with multiple peers to
  cross-check bootstrap node responses.
- Bootstrap nodes SHOULD rate-limit requests (Section 3.4).

Limitations (v1):
- No protocol-level mechanism to detect a malicious bootstrap node.
- No mechanism to verify bootstrap node honesty.
- Bootstrap nodes can enumerate all connecting agents (privacy concern,
  see Section 8.5).

### 8.5 Privacy

AgentRecords are public by design. They contain AgentId, public key,
capabilities, and endpoints. Agents that wish to remain private
SHOULD NOT advertise in the DHT and SHOULD connect only to known
peers.

Future versions MAY support private discovery via:
- Private AgentRecords (encrypted, shared only with authorized peers)
- Relay-based discovery (agent is behind a relay, real address hidden)

## 9. IANA Considerations

- **Region codes**: 0–4 defined, 5–255 reserved.
- **RPC method names**: `aafp.discovery.*` namespace.

## 10. References

- RFC 2119: Key words for use in RFCs
- RFC-0001: AAFP Protocol Overview
- RFC-0002: AAFP Transport & Framing
- RFC-0003: AAFP Identity & Authentication
