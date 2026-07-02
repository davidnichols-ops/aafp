"""Test: Real Python MCP SDK client connects to Rust rmcp server over AAFP.

This test uses the official @modelcontextprotocol/python-sdk (mcp 1.x) to
create a real MCP client session that connects to a Rust rmcp server via
AAFP's post-quantum QUIC transport.

The test verifies:
1. The AAFP transport adapter (aafp_mcp_client) correctly bridges between
   the AAFP PyO3 extension and the MCP SDK's anyio memory-stream interface.
2. The MCP initialize handshake succeeds (protocolVersion negotiated).
3. tools/list returns the echo tool from the Rust server.
4. tools/call executes the echo tool and returns the expected result.
5. The connection closes cleanly with no segfault.
"""
import asyncio
import json
import os
import signal
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.asyncio


async def _wait_for_server(proc, timeout_s=60):
    """Read server stdout until it prints the listening address.

    Returns the ``quic://...`` address or ``None`` on timeout.
    """
    addr = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        line = await asyncio.get_event_loop().run_in_executor(
            None, proc.stdout.readline
        )
        if line:
            print(f"[server] {line.strip()}", flush=True)
            if "listening on:" in line:
                addr = line.split("listening on:")[1].strip()
                break
        else:
            await asyncio.sleep(0.1)
    return addr


async def test_mcp_sdk_client_to_rust_server():
    """Python MCP SDK client → Rust rmcp server over AAFP."""
    import aafp_py
    from aafp_transport import aafp_mcp_client
    from mcp.client.session import ClientSession

    # 1. Start the Rust MCP server (mcp_server example — server-only, long-lived)
    rust_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", ".."
    )
    rust_dir = os.path.abspath(rust_dir)

    proc = subprocess.Popen(
        ["cargo", "run", "--example", "mcp_server", "-p", "aafp-transport-mcp"],
        cwd=rust_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    agent = None
    try:
        # 2. Wait for the server to print its address
        addr = await _wait_for_server(proc, timeout_s=120)
        if addr is None:
            stderr = proc.stderr.read()
            pytest.skip(f"Could not start Rust MCP server: {stderr}")

        print(f"[client] Connecting to {addr}")

        # 3. Create Python AAFP agent
        agent = await aafp_py.Agent.bind("127.0.0.1:0")
        print(f"[client] Agent ID: {agent.agent_id[:16]}...")

        # 4. Connect using the AAFP MCP transport adapter and real MCP SDK
        async with aafp_mcp_client(agent, addr) as (read_stream, write_stream):
            async with ClientSession(
                read_stream,
                write_stream,
            ) as session:
                # 5. Initialize the MCP session
                init_result = await session.initialize()
                print(
                    f"[client] Initialized: server={init_result.serverInfo.name} "
                    f"v{init_result.serverInfo.version} "
                    f"protocol={init_result.protocolVersion}"
                )
                assert init_result.serverInfo.name == "aafp-echo-server"

                # 6. List tools
                tools_result = await session.list_tools()
                tool_names = [t.name for t in tools_result.tools]
                print(f"[client] Available tools: {tool_names}")
                assert "echo" in tool_names, f"echo tool not found in {tool_names}"

                # 7. Call the echo tool
                call_result = await session.call_tool(
                    "echo", {"message": "Hello from AAFP!"}
                )
                assert not call_result.isError, "echo tool returned an error"
                # Extract text content
                text_parts = [
                    c.text for c in call_result.content if hasattr(c, "text")
                ]
                result_text = " ".join(text_parts)
                print(f"[client] Echo result: {result_text}")
                assert "Hello from AAFP!" in result_text

        print("[client] Session closed cleanly")

    finally:
        # Clean up: shut down Python agent first (prevents segfault), then kill server
        if agent is not None:
            await agent.shutdown()
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


async def test_mcp_sdk_clean_shutdown_no_segfault():
    """Verify the full MCP SDK interop flow exits cleanly (no segfault).

    This is the regression test for C1's pyo3 segfault fix, exercised
    through the real MCP SDK path. If quinn's background tasks are not
    drained, the process will segfault during interpreter teardown.
    """
    import aafp_py
    from aafp_transport import aafp_mcp_client
    from mcp.client.session import ClientSession

    rust_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", ".."
    )
    rust_dir = os.path.abspath(rust_dir)

    proc = subprocess.Popen(
        ["cargo", "run", "--example", "mcp_server", "-p", "aafp-transport-mcp"],
        cwd=rust_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    agent = None
    try:
        addr = await _wait_for_server(proc, timeout_s=120)
        if addr is None:
            stderr = proc.stderr.read()
            pytest.skip(f"Could not start Rust MCP server: {stderr}")

        agent = await aafp_py.Agent.bind("127.0.0.1:0")

        async with aafp_mcp_client(agent, addr) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                await session.list_tools()

        # The key: clean shutdown of the Python agent drains quinn tasks
        await agent.shutdown()
        agent = None

    finally:
        if agent is not None:
            await agent.shutdown()
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
