"""Type stubs for the AAFP high-level Python API."""
from __future__ import annotations

from typing import Optional, Awaitable, Callable, Any

class Request:
    """A simple request from a caller to an agent."""
    body: str
    """The text body of the request."""
    payload: Optional[bytes]
    """The binary payload, or None."""

    @staticmethod
    def text(body: str) -> Request:
        """Create a text request."""
        ...

    @staticmethod
    def data(data: bytes) -> Request:
        """Create a binary data request."""
        ...

class Response:
    """A simple response from an agent to a caller."""
    body: str
    """The text body of the response."""
    payload: Optional[bytes]
    """The binary payload, or None."""

    @staticmethod
    def text(body: str) -> Response:
        """Create a text response."""
        ...

    @staticmethod
    def data(data: bytes) -> Response:
        """Create a binary data response."""
        ...

class ServeBuilder:
    """Builder for serving an agent. Chain methods then call .start()."""

    def capability(self, cap: str) -> None:
        """Add a capability this agent provides."""
        ...

    def handler(self, handler: Callable[[Request], Awaitable[Response]]) -> None:
        """Set the request handler function."""
        ...

    def bind(self, addr: str) -> None:
        """Set the bind address (default: 0.0.0.0:0)."""
        ...

    def start(self) -> Awaitable[ServingAgent]:
        """Build and start the agent. Returns a coroutine that resolves to a ServingAgent."""
        ...

class ServingAgent:
    """A running agent that is serving requests."""
    id: str
    """The agent's ID as a hex string."""
    addr: str
    """The agent's address (e.g., 'quic://127.0.0.1:12345')."""

    def stop(self) -> None:
        """Stop the serving agent."""
        ...

class ConnectedAgent:
    """A connected agent that can discover and call other agents."""
    id: str
    """The agent's ID as a hex string."""

    def discover(self, capability: str) -> DiscoveryBuilder:
        """Discover agents by capability."""
        ...

    def call_at(self, addr: str, request: Request) -> Awaitable[Response]:
        """Call an agent at a specific address, bypassing discovery."""
        ...

class DiscoveryBuilder:
    """Builder for discovering and calling an agent."""

    def call(self, request: Request) -> Awaitable[Response]:
        """Call the discovered agent with a request."""
        ...

class Agent:
    """Top-level entry point for the simple API."""

    @staticmethod
    def serve(capability: str) -> ServeBuilder:
        """Start serving an agent. Returns a ServeBuilder."""
        ...

    @staticmethod
    def connect() -> Awaitable[ConnectedAgent]:
        """Connect to the network. Returns a coroutine that resolves to a ConnectedAgent."""
        ...
