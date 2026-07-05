"""Tests for the AAFP high-level Python API (P2.4)."""
import asyncio
import pytest
from aafp import Agent, Request, Response


@pytest.mark.asyncio
async def test_request_text():
    """Test Request.text() creates a request with the correct body."""
    req = Request.text("hello")
    assert req.body == "hello"
    assert req.payload is None


@pytest.mark.asyncio
async def test_request_data():
    """Test Request.data() creates a request with the correct payload."""
    req = Request.data(b"\x01\x02\x03")
    assert req.payload == b"\x01\x02\x03"
    assert req.body == ""


@pytest.mark.asyncio
async def test_response_text():
    """Test Response.text() creates a response with the correct body."""
    resp = Response.text("world")
    assert resp.body == "world"
    assert resp.payload is None


@pytest.mark.asyncio
async def test_response_data():
    """Test Response.data() creates a response with the correct payload."""
    resp = Response.data(b"\x04\x05\x06")
    assert resp.payload == b"\x04\x05\x06"
    assert resp.body == ""


@pytest.mark.asyncio
async def test_connect():
    """Test that Agent.connect() returns a ConnectedAgent."""
    agent = await Agent.connect()
    assert agent is not None
    assert len(agent.id) == 64  # 32 bytes = 64 hex chars


@pytest.mark.asyncio
async def test_serve_and_call_at():
    """Test that a Python agent can serve and be called via call_at."""
    # Serve an echo agent with a Python handler
    builder = Agent.serve("echo")
    builder.bind("127.0.0.1:0")

    async def echo_handler(request):
        return Response.text(f"echo: {request.body}")

    builder.handler(echo_handler)
    server = await builder.start()

    # Give the server time to bind
    await asyncio.sleep(0.1)

    # Call it directly by address
    client = await Agent.connect()
    result = await client.call_at(server.addr, Request.text("hello"))
    assert result.body == "echo: hello"

    # Clean up
    server.stop()


@pytest.mark.asyncio
async def test_serve_addr_and_id():
    """Test that a serving agent has a valid address and ID."""
    builder = Agent.serve("test")

    async def handler(req):
        return Response.text("ok")

    builder.handler(handler)
    builder.bind("127.0.0.1:0")
    server = await builder.start()

    # Should have a valid address
    assert "127.0.0.1" in server.addr

    # Should have a valid ID (64 hex chars)
    assert len(server.id) == 64

    server.stop()


@pytest.mark.asyncio
async def test_discover_no_agents():
    """Test that discover errors when no agents are found."""
    client = await Agent.connect()
    with pytest.raises(Exception):
        result = await client.discover("nonexistent").call(Request.text("test"))
