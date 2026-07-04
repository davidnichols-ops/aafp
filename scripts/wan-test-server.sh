#!/usr/bin/env bash
#
# wan-test-server.sh — Start an AAFP agent in server mode for WAN testing.
#
# The server listens on a configurable port and handles ping, echo, streaming,
# and discovery requests from remote test clients. It logs all connections
# and requests to stderr.
#
# Usage:
#   ./scripts/wan-test-server.sh [PORT]
#
# Environment variables:
#   AAFP_SERVER_PORT  — port to bind (default: 4433)
#   AAFP_SERVER_BIND  — bind address (default: 0.0.0.0)
#   AAFP_LOG_LEVEL    — tracing log level (default: info)
#
# The server prints its multiaddr on stdout once it is ready:
#   Server listening on: quic://0.0.0.0:4433
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PORT="${AAFP_SERVER_PORT:-${1:-4433}}"
BIND="${AAFP_SERVER_BIND:-0.0.0.0}"
LOG_LEVEL="${AAFP_LOG_LEVEL:-info}"

export AAFP_SERVER_PORT="${PORT}"
export AAFP_SERVER_BIND="${BIND}"

echo "[wan-server] Starting AAFP WAN test server on ${BIND}:${PORT}" >&2
echo "[wan-server] Log level: ${LOG_LEVEL}" >&2

cd "${RUST_DIR}"

# Run the wan-test-server example binary.
exec cargo run --example wan_test_server -p aafp-tests -- "${BIND}:${PORT}"
