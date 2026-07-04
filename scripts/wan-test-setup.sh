#!/usr/bin/env bash
#
# wan-test-setup.sh — Set up and run a complete WAN test between two agents.
#
# This script is designed for single-machine testing (localhost simulation)
# but documents the two-machine setup. When run on a single machine, it
# starts a local server and connects a local client to it.
#
# For real two-machine testing:
#   Machine A (server): ./scripts/wan-test-server.sh 4433
#   Machine B (client): ./scripts/wan-test-client.sh quic://<machine-a-ip>:4433 ping
#
# Usage (single-machine simulation):
#   ./scripts/wan-test-setup.sh [TEST_MODE] [MSG_COUNT] [MSG_SIZE]
#
# Arguments:
#   TEST_MODE  — ping|echo|stream|handshake|discovery|migration (default: ping)
#   MSG_COUNT  — number of messages (default: 1000)
#   MSG_SIZE   — message size in bytes (default: 1024)
#
# Environment variables:
#   AAFP_CONGESTION — congestion controller: cubic|bbr|newreno (default: cubic)
#   AAFP_RESULTS_DIR — results directory (default: ../../test-results/interop)
#
# Output:
#   JSON results written to ${AAFP_RESULTS_DIR}/wan-<mode>-<timestamp>.json
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TEST_MODE="${1:-ping}"
MSG_COUNT="${2:-1000}"
MSG_SIZE="${3:-1024}"
CONGESTION="${AAFP_CONGESTION:-cubic}"

if [[ -z "${AAFP_RESULTS_DIR:-}" ]]; then
    AAFP_RESULTS_DIR="$(cd "${RUST_DIR}/../.." && pwd)/test-results/interop"
fi
mkdir -p "${AAFP_RESULTS_DIR}"

TIMESTAMP="$(date +%Y%m%dT%H%M%S)"
RESULTS_FILE="${AAFP_RESULTS_DIR}/wan-${TEST_MODE}-${TIMESTAMP}.json"

echo "============================================" >&2
echo "AAFP WAN Test Setup (localhost simulation)" >&2
echo "============================================" >&2
echo "Test mode:    ${TEST_MODE}" >&2
echo "Messages:     ${MSG_COUNT} x ${MSG_SIZE}B" >&2
echo "Congestion:   ${CONGESTION}" >&2
echo "Results file: ${RESULTS_FILE}" >&2
echo "============================================" >&2

cd "${RUST_DIR}"

# Start the server in the background.
echo "[setup] Starting WAN test server..." >&2
cargo run --example wan_test_server -p aafp-tests -- "127.0.0.1:0" 2>"${RUST_DIR}/target/wan-server.log" &
SERVER_PID=$!

# Give the server time to start and print its address.
sleep 3

# Read the server address from the log file.
SERVER_ADDR=$(grep -m1 "Server listening on:" "${RUST_DIR}/target/wan-server.log" 2>/dev/null | sed 's/.*Server listening on: //')
if [[ -z "${SERVER_ADDR}" ]]; then
    echo "[setup] ERROR: Could not determine server address from log." >&2
    echo "[setup] Server log:" >&2
    cat "${RUST_DIR}/target/wan-server.log" >&2
    kill "${SERVER_PID}" 2>/dev/null || true
    exit 1
fi

echo "[setup] Server address: ${SERVER_ADDR}" >&2

# Run the client test.
echo "[setup] Running client test..." >&2
export AAFP_REMOTE_ADDR="${SERVER_ADDR}"
export AAFP_TEST_MODE="${TEST_MODE}"
export AAFP_MSG_COUNT="${MSG_COUNT}"
export AAFP_MSG_SIZE="${MSG_SIZE}"
export AAFP_CONGESTION="${CONGESTION}"
export AAFP_RESULTS_FILE="${RESULTS_FILE}"

set +e
cargo run --example wan_test_client -p aafp-tests -- \
    "${SERVER_ADDR}" "${TEST_MODE}" "${RESULTS_FILE}"
CLIENT_EXIT=$?
set -e

# Clean up the server.
echo "[setup] Stopping server (PID ${SERVER_PID})..." >&2
kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true

if [[ ${CLIENT_EXIT} -eq 0 ]]; then
    echo "[setup] Test completed successfully." >&2
    echo "[setup] Results: ${RESULTS_FILE}" >&2
else
    echo "[setup] Test FAILED (exit code ${CLIENT_EXIT})." >&2
fi

exit ${CLIENT_EXIT}
