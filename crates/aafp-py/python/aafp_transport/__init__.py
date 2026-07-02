"""AAFP post-quantum transport for Python MCP clients.

This package provides a transport adapter that allows Python MCP clients
to connect to MCP servers over AAFP's post-quantum QUIC transport.
"""
from .transport import AafpTransport
from .mcp_adapter import AafpMcpTransport

__all__ = ["AafpTransport", "AafpMcpTransport"]
__version__ = "0.1.0"
