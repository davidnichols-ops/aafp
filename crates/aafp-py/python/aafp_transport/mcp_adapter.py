"""MCP SDK Transport adapter for AAFP.

This adapter allows the Python MCP SDK (modelcontextprotocol/python-sdk)
to use AAFP as a transport. It follows the same pattern as the SDK's
built-in transports (``stdio_client``, ``websocket_client``): an async
context manager that yields ``(read_stream, write_stream)`` of anyio
``MemoryObjectStream`` carrying :class:`mcp.shared.session.SessionMessage`
objects.

Usage with the Python MCP SDK::

    from mcp.client.session import ClientSession
    from aafp_transport import aafp_mcp_client
    import aafp_py

    agent = await aafp_py.Agent.bind("127.0.0.1:0")
    async with aafp_mcp_client(agent, "quic://127.0.0.1:4433") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()

The legacy :class:`AafpMcpTransport` class is kept for backward compatibility
with the raw JSON-RPC tests in ``test_aafp_mcp.py``.
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from pydantic import ValidationError

import mcp.types as types
from mcp.shared.message import SessionMessage

from .transport import AafpTransport


@asynccontextmanager
async def aafp_mcp_client(
    agent: "aafp_py.Agent",
    addr: str,
) -> AsyncGenerator[
    tuple[
        MemoryObjectReceiveStream[SessionMessage | Exception],
        MemoryObjectSendStream[SessionMessage],
    ],
    None,
]:
    """AAFP client transport for the Python MCP SDK.

    Connects ``agent`` to the AAFP MCP server at ``addr`` (e.g.
    ``"quic://127.0.0.1:4433"``) and yields ``(read_stream, write_stream)``:

    - ``read_stream``: read :class:`SessionMessage` objects received from the
      server (or ``Exception`` objects on validation failure).
    - ``write_stream``: write :class:`SessionMessage` objects to send them to
      the server over AAFP's post-quantum QUIC transport.
    """
    read_stream: MemoryObjectReceiveStream[SessionMessage | Exception]
    read_stream_writer: MemoryObjectSendStream[SessionMessage | Exception]
    write_stream: MemoryObjectSendStream[SessionMessage]
    write_stream_reader: MemoryObjectReceiveStream[SessionMessage]

    read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

    transport = AafpTransport()
    await transport.connect(agent, addr)

    try:
        async def aafp_reader():
            """Read JSON-RPC messages from AAFP and feed read_stream."""
            async with read_stream_writer:
                while True:
                    try:
                        raw = await transport.receive()
                    except anyio.ClosedResourceError:
                        break
                    except Exception as exc:  # pragma: no cover - transport error
                        await read_stream_writer.send(exc)
                        break
                    try:
                        if isinstance(raw, str):
                            message = types.JSONRPCMessage.model_validate_json(raw)
                        else:
                            message = types.JSONRPCMessage.model_validate(raw)
                        await read_stream_writer.send(SessionMessage(message))
                    except ValidationError as exc:
                        await read_stream_writer.send(exc)
                    except Exception as exc:  # pragma: no cover
                        await read_stream_writer.send(exc)

        async def aafp_writer():
            """Serialize SessionMessages from write_stream and send via AAFP."""
            async with write_stream_reader:
                async for session_message in write_stream_reader:
                    msg_dict = session_message.message.model_dump(
                        by_alias=True, mode="json", exclude_none=True
                    )
                    await transport.send(msg_dict)

        async with anyio.create_task_group() as tg:
            tg.start_soon(aafp_reader)
            tg.start_soon(aafp_writer)
            yield (read_stream, write_stream)
            tg.cancel_scope.cancel()
    finally:
        await transport.close()


class AafpMcpTransport:
    """Legacy AAFP transport with ``read``/``write`` methods.

    .. deprecated::
        Use :func:`aafp_mcp_client` for compatibility with the real Python
        MCP SDK, which expects anyio memory streams rather than
        ``read``/``write`` callables.

    Kept for the raw JSON-RPC interop tests in ``test_aafp_mcp.py``.
    """

    def __init__(self):
        self._transport = AafpTransport()

    async def connect(self, agent, addr: str) -> None:
        """Connect to an AAFP MCP server."""
        await self._transport.connect(agent, addr)

    async def accept(self, agent) -> None:
        """Accept an AAFP connection (server side)."""
        await self._transport.accept(agent)

    async def read(self) -> dict:
        """Read a message (raw JSON-RPC dict)."""
        return await self._transport.receive()

    async def write(self, message: dict) -> None:
        """Write a message (raw JSON-RPC dict)."""
        await self._transport.send(message)

    async def close(self) -> None:
        """Close the transport."""
        await self._transport.close()

    @property
    def peer_agent_id(self) -> Optional[str]:
        return self._transport.peer_agent_id
