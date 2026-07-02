# AAFP Python ↔ Rust MCP Interop Results

## Test: Python MCP SDK client → Rust rmcp server over AAFP

**Date:** 2026-07-02
**Python MCP SDK version:** 1.28.1 (`pip install mcp`)
**rmcp version:** 1.8.0 (Rust MCP SDK)
**AAFP version:** rev6-rc1
**Python version:** 3.14.6
**Rust version:** 1.96.0
**Platform:** macOS 15.5.0, Apple M4

### Results
- [x] Transport connects (AAFP handshake completes — QUIC + PQ TLS + ML-DSA-65)
- [x] MCP initialize succeeds (protocolVersion 2025-11-25 negotiated)
- [x] tools/list returns tools (1 tool: `echo`)
- [x] tools/call executes (echo tool returns "Echo: Hello from AAFP!")
- [x] Graceful close (no segfault — C1 fix verified through MCP SDK path)

### Verified
- Python MCP SDK client can use AAFP as a transport via the `aafp_mcp_client` adapter
- The adapter correctly bridges between AAFP's PyO3 async transport and the MCP SDK's
  anyio `MemoryObjectSendStream`/`MemoryObjectReceiveStream` interface
- JSON-RPC messages are correctly carried in AAFP DATA frames
- ML-DSA-65 identity verification works across the PyO3 boundary
- Post-quantum QUIC transport (X25519MLKEM768) works end-to-end
- Concurrent send/receive works (fixed PyO3 transport mutex deadlock — send and
  receive now use separate locks via `send_handle()`)

### Adapter Architecture

The Python MCP SDK (v1.x) uses anyio memory object streams, not `read`/`write`
callables. The `aafp_mcp_client` async context manager:

1. Creates two anyio `MemoryObjectStream` pairs (read + write)
2. Connects the AAFP transport (QUIC + handshake)
3. Spawns `aafp_reader` and `aafp_writer` tasks that bridge between the AAFP
   transport and the anyio streams
4. Yields `(read_stream, write_stream)` for use with `ClientSession`

```python
from aafp_transport import aafp_mcp_client
from mcp.client.session import ClientSession

async with aafp_mcp_client(agent, "quic://127.0.0.1:4433") as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        result = await session.call_tool("echo", {"message": "Hello!"})
```

### Bug Fixed During D1

The original PyO3 `PyAafpTransport` wrapped the entire `AafpMcpTransport` in a
single `Arc<Mutex<Option<_>>>`, which serialized send and receive operations.
When the MCP SDK's reader task blocked waiting for a response, the writer task
could not acquire the lock to send the request — a classic deadlock. This was
not visible in the raw JSON-RPC tests (which call send/receive sequentially)
but manifested immediately with the real MCP SDK (which runs reader and writer
concurrently via anyio task groups).

**Fix:** Added `send_handle()` and `send_raw_json_on_handle()` to
`AafpMcpTransport`. The PyO3 wrapper now stores the send handle separately,
so `send()` only locks the send stream's own mutex, not the entire transport.
`receive()` locks the transport mutex independently. Send and receive can
now run concurrently.

### Limitations
- None identified. The interop is fully functional.
