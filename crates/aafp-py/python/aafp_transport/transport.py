"""Low-level AAFP transport wrapper.

This wraps the aafp_py PyO3 extension module and provides a clean
async Python API for connecting, sending, and receiving AAFP frames.
"""
from typing import Any, Optional

import aafp_py


class AafpTransport:
    """Async AAFP transport for JSON-RPC messages."""

    def __init__(self):
        self._inner = aafp_py.AafpTransport()
        self._closed = False

    async def connect(self, agent: "aafp_py.Agent", addr: str) -> None:
        """Connect to an AAFP server (client side)."""
        await self._inner.connect(agent, addr)

    async def accept(self, agent: "aafp_py.Agent") -> None:
        """Accept an AAFP connection (server side)."""
        await self._inner.accept(agent)

    async def send(self, message: dict) -> None:
        """Send a JSON-RPC message as an AAFP DATA frame."""
        if self._closed:
            raise RuntimeError("Transport is closed")
        await self._inner.send(message)

    async def receive(self) -> dict:
        """Receive a JSON-RPC message from an AAFP DATA frame."""
        if self._closed:
            raise RuntimeError("Transport is closed")
        # The PyO3 binding returns a JSON string; parse it to a dict
        import json
        result = await self._inner.receive()
        if isinstance(result, str):
            return json.loads(result)
        return result

    async def close(self) -> None:
        """Close the transport gracefully."""
        if not self._closed:
            await self._inner.close()
            self._closed = True

    @property
    def peer_agent_id(self) -> Optional[str]:
        """The verified peer AgentId (hex string), or None."""
        return self._inner.peer_agent_id
