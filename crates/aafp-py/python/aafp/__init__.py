"""AAFP — Agent-Agent First Networking Protocol.

High-level Python API for building and calling agents.

Usage::

    from aafp import Agent, Request, Response

    # Serve an agent
    builder = Agent.serve("echo")
    builder.handler(echo_handler)
    agent = await builder.start()

    # Call an agent
    client = await Agent.connect()
    result = await client.call_at(agent.addr, Request.text("hello"))
    print(result.body)
"""
import aafp_py

from aafp_py import (
    Request,
    Response,
    SimpleAgent as Agent,
    ServeBuilder,
    ServingAgent,
    ConnectedAgent,
    DiscoveryBuilder,
)

__all__ = [
    "Agent",
    "Request",
    "Response",
    "ServeBuilder",
    "ServingAgent",
    "ConnectedAgent",
    "DiscoveryBuilder",
]
__version__ = "0.1.0"
