"""Test: Python MCP client connects to Rust rmcp server over AAFP.

This test starts a Rust MCP server (using the mcp_over_aafp example binary)
and connects a Python client via the AafpMcpTransport adapter.
"""
import asyncio
import json
import os
import signal
import subprocess
import sys
import time

import pytest

# Mark all tests in this module as async
pytestmark = pytest.mark.asyncio


async def test_python_client_rust_server():
    """Python client connects to Rust server, calls tools/list."""
    # 1. Start Rust MCP server (mcp_over_aafp example)
    rust_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "implementations", "rust"
    )
    rust_dir = os.path.abspath(rust_dir)

    # Build and run the example
    proc = subprocess.Popen(
        ["cargo", "run", "--example", "mcp_over_aafp"],
        cwd=rust_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # Wait for the server to print its address
        # The example prints "Server agent listening on: quic://127.0.0.1:PORT"
        addr = None
        for _ in range(100):  # 10 second timeout
            line = proc.stdout.readline()
            if line:
                print(f"[server] {line.strip()}")
                if "listening on:" in line:
                    addr = line.split("listening on:")[1].strip()
                    break
            else:
                await asyncio.sleep(0.1)

        if addr is None:
            stderr = proc.stderr.read()
            pytest.skip(f"Could not start Rust MCP server: {stderr}")

        print(f"[client] Connecting to {addr}")

        # 2. Create Python agent and connect
        import aafp_py
        from aafp_transport import AafpMcpTransport

        agent = await aafp_py.Agent.bind("127.0.0.1:0")
        transport = AafpMcpTransport()
        await transport.connect(agent, addr)

        # 3. Send initialize request
        await transport.write({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "python-test", "version": "0.1.0"},
            },
            "id": 1,
        })
        response = await transport.read()
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert "result" in response

        # 4. Send initialized notification
        await transport.write({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        })

        # 5. Send tools/list
        await transport.write({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2,
        })
        response = await transport.read()
        assert "result" in response
        assert "tools" in response["result"]

        # 6. Clean close
        await transport.close()

    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


async def test_transport_basic():
    """Basic test: create agent and transport objects."""
    import aafp_py
    from aafp_transport import AafpTransport

    agent = await aafp_py.Agent.bind("127.0.0.1:0")
    assert agent.agent_id is not None
    assert len(agent.agent_id) == 64  # 32 bytes hex = 64 chars

    transport = AafpTransport()
    assert transport.peer_agent_id is None  # not connected yet
