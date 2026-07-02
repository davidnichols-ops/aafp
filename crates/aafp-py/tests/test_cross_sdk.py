"""Test: Rust rmcp client connects to Python MCP server over AAFP.

This is the reverse direction of test_aafp_mcp.py — a Python process
acts as the MCP server, and a Rust binary (mcp_client example) acts
as the MCP client.

This completes the cross-SDK interop proof point (B2.11).
"""
import asyncio
import json
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.asyncio


async def test_rust_client_python_server():
    """Rust client connects to Python server, exchanges MCP messages."""
    import aafp_py
    from aafp_transport import AafpTransport

    # 1. Start Python MCP server (in-process)
    server_agent = await aafp_py.Agent.bind("127.0.0.1:0")
    server_addr = server_agent.multiaddr
    print(f"[server] Python server listening on: {server_addr}")

    # We need two transport objects: one for accept, one for the accepted connection.
    # The PyO3 AafpTransport.accept() sets the inner transport on the same object,
    # so we use the raw aafp_py.AafpTransport for accept and then wrap it.
    raw_server_transport = aafp_py.AafpTransport()

    # Accept in background — this will complete when the Rust client connects
    accept_task = asyncio.ensure_future(raw_server_transport.accept(server_agent))

    # Give the server a moment to be ready
    await asyncio.sleep(0.2)

    # 2. Start Rust MCP client (subprocess)
    rust_dir = os.path.join(
        os.path.dirname(__file__), "..", ".."
    )
    rust_dir = os.path.abspath(rust_dir)

    proc = await asyncio.create_subprocess_exec(
        "cargo", "run", "--example", "mcp_client", "--", server_addr,
        cwd=rust_dir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        # 3. Wait for the accept to complete (Rust client connects)
        await asyncio.wait_for(accept_task, timeout=30.0)
        print("[server] Rust client connected")

        # Now use the raw transport for send/receive.
        # The raw aafp_py.AafpTransport.receive() returns a JSON string,
        # so we need to parse it with json.loads().
        # 4. Wait for the Rust client to send initialize
        raw_request = await asyncio.wait_for(raw_server_transport.receive(), timeout=30.0)
        request = json.loads(raw_request) if isinstance(raw_request, str) else raw_request
        print(f"[server] Received: {request}")
        assert request["jsonrpc"] == "2.0"
        assert request["method"] == "initialize"
        assert "params" in request

        # 5. Python server sends initialize response
        await raw_server_transport.send({
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {"name": "python-aafp-server", "version": "0.1.0"},
            },
        })

        # 6. Receive initialized notification (no response expected)
        raw_notif = await asyncio.wait_for(raw_server_transport.receive(), timeout=10.0)
        notif = json.loads(raw_notif) if isinstance(raw_notif, str) else raw_notif
        print(f"[server] Received: {notif}")
        assert notif["jsonrpc"] == "2.0"
        assert notif["method"] == "notifications/initialized"

        # 7. Receive tools/list request
        raw_tools_req = await asyncio.wait_for(raw_server_transport.receive(), timeout=10.0)
        tools_req = json.loads(raw_tools_req) if isinstance(raw_tools_req, str) else raw_tools_req
        print(f"[server] Received: {tools_req}")
        assert tools_req["jsonrpc"] == "2.0"
        assert tools_req["method"] == "tools/list"

        # 8. Python server sends tools/list response
        await raw_server_transport.send({
            "jsonrpc": "2.0",
            "id": tools_req.get("id"),
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echoes back the input message",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "message": {
                                    "type": "string",
                                    "description": "The message to echo back",
                                }
                            },
                            "required": ["message"],
                        },
                    }
                ],
            },
        })

        # 9. Wait for the Rust client to finish
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        print(f"[client] stdout: {stdout.decode() if stdout else ''}")
        print(f"[client] stderr: {stderr.decode() if stderr else ''}")

        # The Rust client should exit with code 0
        assert proc.returncode == 0, f"Rust client exited with {proc.returncode}"

    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        await raw_server_transport.close()
        await server_agent.shutdown()
