"""MCP SDK Transport adapter for AAFP.

This adapter allows the Python MCP SDK (modelcontextprotocol/python-sdk)
to use AAFP as a transport. It implements the SDK's Transport protocol.
"""
from typing import Any, Optional

from .transport import AafpTransport


class AafpMcpTransport:
    """AAFP transport implementing the MCP SDK Transport protocol.

    Usage with the Python MCP SDK:

        from mcp.client.session import ClientSession
        from aafp_transport import AafpMcpTransport, AafpTransport
        import aafp_py

        agent = await aafp_py.Agent.bind("127.0.0.1:0")
        transport = AafpMcpTransport()
        await transport.connect(agent, "quic://127.0.0.1:4433")

        async with ClientSession(transport.read, transport.write) as session:
            await session.initialize()
            tools = await session.list_tools()
    """

    def __init__(self):
        self._transport = AafpTransport()

    async def connect(self, agent, addr: str) -> None:
        """Connect to an AAFP MCP server."""
        await self._transport.connect(agent, addr)

    async def accept(self, agent) -> None:
        """Accept an AAFP MCP connection (server side)."""
        await self._transport.accept(agent)

    async def read(self) -> dict:
        """Read a message (MCP SDK Transport protocol)."""
        return await self._transport.receive()

    async def write(self, message: dict) -> None:
        """Write a message (MCP SDK Transport protocol)."""
        await self._transport.send(message)

    async def close(self) -> None:
        """Close the transport."""
        await self._transport.close()

    @property
    def peer_agent_id(self) -> Optional[str]:
        return self._transport.peer_agent_id
