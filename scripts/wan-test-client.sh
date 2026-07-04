#!/usr/bin/env bash
#
# wan-test-client.sh — Connect to a remote AAFP server and run a test suite.
#
# The client connects to the specified remote address, runs the configured
# test mode (ping, echo, stream, handshake, discovery, migration), and
# outputs JSON results to stdout (and optionally to a file).
#
# Usage:
#   ./scripts/wan-test-client.sh <REMOTE_ADDR> [TEST_MODE]
#
# Arguments:
#   REMOTE_ADDR  — remote server multiaddr, e.g. quic://remote.host:4433
#   TEST_MODE    — test mode: ping|echo|stream|handshake|discovery|migration
#                  (default: ping)
#
# Environment variables:
#   AAFP_REMOTE_ADDR  — remote server address (overrides positional arg)
#   AAFP_TEST_MODE    — test mode (overrides positional arg)
#   AAFP_MSG_COUNT    — number of messages for ping/throughput (default: 1000)
#   AAFP_MSG_SIZE     — message size in bytes (default: 1024)
#   AAFP_RESULTS_DIR  — directory to write JSON results (default: ../../test-results/interop)
#   AAFP_CONGESTION   — congestion controller: cubic|bbr|newreno (default: cubic)
#
# Output:
#   JSON results are written to stdout and to
#   ${AAFP_RESULTS_DIR}/wan-<mode>-<timestamp>.json
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

REMOTE_ADDR="${AAFP_REMOTE_ADDR:-${1:-}}"
TEST_MODE="${AAFP_TEST_MODE:-${2:-ping}}"
MSG_COUNT="${AAFP_MSG_COUNT:-1000}"
MSG_SIZE="${AAFP_MSG_SIZE:-1024}"
CONGESTION="${AAFP_CONGESTION:-cubic}"

if [[ -z "${REMOTE_ADDR}" ]]; then
    echo "Error: REMOTE_ADDR is required." >&2
    echo "Usage: $0 <REMOTE_ADDR> [TEST_MODE]" >&2
    echo "  REMOTE_ADDR: quic://remote.host:4433" >&2
    echo "  TEST_MODE:   ping|echo|stream|handshake|discovery|migration" >&2
    exit 1
fi

# Default results directory (relative to repo root).
if [[ -z "${AAFP_RESULTS_DIR:-}" ]]; then
    AAFP_RESULTS_DIR="$(cd "${RUST_DIR}/../.." && pwd)/test-results/interop"
fi
mkdir -p "${AAFP_RESULTS_DIR}"

TIMESTAMP="$(date +%Y%m%dT%H%M%S)"
RESULTS_FILE="${AAFP_RESULTS_DIR}/wan-${TEST_MODE}-${TIMESTAMP}.json"

echo "[wan-client] Connecting to ${REMOTE_ADDR}" >&2
echo "[wan-client] Test mode: ${TEST_MODE}" >&2
echo "[wan-client] Messages: ${MSG_COUNT} x ${MSG_SIZE}B" >&2
echo "[wan-client] Congestion: ${CONGESTION}" >&2
echo "[wan-client] Results file: ${RESULTS_FILE}" >&2

cd "${RUST_DIR}"

export AAFP_REMOTE_ADDR="${REMOTE_ADDR}"
export AAFP_TEST_MODE="${TEST_MODE}"
export AAFP_MSG_COUNT="${MSG_COUNT}"
export AAFP_MSG_SIZE="${MSG_SIZE}"
export AAFP_CONGESTION="${CONGESTION}"
export AAFP_RESULTS_FILE="${RESULTS_FILE}"

# Run the wan-test-client example binary.
cargo run --example wan_test_client -p aafp-tests -- \
    "${REMOTE_ADDR}" "${TEST_MODE}" "${RESULTS_FILE}"
