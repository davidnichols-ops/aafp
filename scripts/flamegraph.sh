#!/usr/bin/env bash
#
# flamegraph.sh — Generate flamegraphs for AAFP benchmarks (Track M2)
#
# Usage:
#   ./scripts/flamegraph.sh <benchmark-name> [-- <extra cargo-flamegraph args>...]
#   ./scripts/flamegraph.sh --all
#   ./scripts/flamegraph.sh --list
#
# Examples:
#   ./scripts/flamegraph.sh mcp_transport_ping
#   ./scripts/flamegraph.sh handshake
#   ./scripts/flamegraph.sh framing
#   ./scripts/flamegraph.sh discovery
#   ./scripts/flamegraph.sh --all
#   ./scripts/flamegraph.sh mcp_transport_ping -- --bench mcp_transport -- --warm-up-time 1
#
# Output:
#   test-results/flamegraphs/<benchmark-name>.svg
#
# What this script does:
#   1. Builds the relevant Criterion benchmark in release mode with debug symbols.
#   2. Profiles it under perf (Linux) or dtrace (macOS) via `cargo flamegraph`.
#   3. Renders an interactive flamegraph SVG.
#   4. Saves the SVG to test-results/flamegraphs/.
#
# Platform notes:
#   - Linux:  uses `perf record`. Requires `perf` and kernel perf_event support.
#             You may need: echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
#             Install flamegraph tool: cargo install flamegraph
#   - macOS:  uses DTrace via `cargo flamegraph`. DTrace requires root and
#             System Integrity Protection (SIP) adjustments. Specifically, the
#             `dtrace` and `perf` (dtrace) probes need to be allowed:
#               csrutil enable --without dtrace
#             (run from macOS Recovery). Then run this script with sudo:
#               sudo ./scripts/flamegraph.sh mcp_transport_ping
#             Alternatively, use the Instruments.app "Time Profiler" template
#             as a GUI alternative that does not require disabling SIP.
#
# This script is a helper that documents the process. It fails gracefully with
# helpful instructions if `cargo-flamegraph` is not installed or if elevated
# privileges are required.
#
# Exit codes:
#   0  success
#   1  generic error
#   2  missing dependency (cargo-flamegraph / perf)
#   3  insufficient privileges (needs sudo on macOS)
#   4  unknown benchmark name
#
set -euo pipefail

# --- Locate workspace root ----------------------------------------------------
# Resolve the directory of this script and the workspace root (the dir that
# contains Cargo.toml and the crates/ directory).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${WORKSPACE_DIR}/test-results/flamegraphs"

mkdir -p "${OUTPUT_DIR}"

# --- Benchmark registry -------------------------------------------------------
# Maps the friendly benchmark name (used in the plan & output filename) to the
# Criterion bench target name (the `--bench <name>` argument) and an optional
# Criterion group filter (passed as a positional filter to the bench binary).
#
# Implemented as a case statement for POSIX/bash-3.2 portability (macOS ships
# bash 3.2 which lacks associative arrays). Returns "bench_target:group_filter"
# on stdout, or returns non-zero if the benchmark is unknown.
#
# group_filter may be empty (profiling the whole bench binary).
benchmark_spec() {
  case "$1" in
    mcp_transport_ping) echo "mcp_transport:mcp_transport_ping" ;;
    handshake)          echo "handshake:" ;;
    framing)            echo "framing:" ;;
    discovery)          echo "discovery:" ;;
    *)                  return 1 ;;
  esac
}

# Ordered list of friendly benchmark names (for --list and --all).
BENCHMARK_NAMES="discovery framing handshake mcp_transport_ping"

# --- Helpers ------------------------------------------------------------------
err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; }
info() { printf '\033[36minfo:\033[0m %s\n' "$*"; }
ok()   { printf '\033[32mok:\033[0m %s\n' "$*"; }

print_benchmarks() {
  echo "Available benchmarks:"
  for name in ${BENCHMARK_NAMES}; do
    echo "  - ${name}"
  done
}

detect_os() {
  case "$(uname -s)" in
    Darwin) echo "macos" ;;
    Linux)  echo "linux" ;;
    *)      echo "unknown" ;;
  esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# --- Dependency checks --------------------------------------------------------
check_cargo_flamegraph() {
  if ! cargo flamegraph --help >/dev/null 2>&1; then
    err "cargo-flamegraph is not installed."
    echo
    echo "Install it with:"
    echo "  cargo install flamegraph"
    echo
    echo "This installs the 'cargo flamegraph' subcommand which wraps perf (Linux)"
    echo "or dtrace (macOS) and the flamegraph rendering scripts."
    return 2
  fi
}

check_perf() {
  if ! have perf; then
    err "'perf' is not installed or not on PATH."
    echo
    echo "On Debian/Ubuntu:  sudo apt-get install linux-tools-common linux-tools-\$(uname -r)"
    echo "On Fedora/RHEL:    sudo dnf install perf"
    echo
    echo "You may also need to relax perf_event_paranoid:"
    echo "  echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
    return 2
  fi
}

check_sudo_macos() {
  if [ "$(id -u)" -ne 0 ]; then
    err "DTrace-based profiling on macOS requires root privileges."
    echo
    echo "Re-run this script with sudo:"
    echo "  sudo $0 $*"
    echo
    echo "Additionally, DTrace probes must be permitted. If you see"
    echo "'dtrace: system integrity protection is on', boot into macOS Recovery"
    echo "and run:"
    echo "  csrutil enable --without dtrace"
    echo
    echo "Alternatively, use Instruments.app (Time Profiler template) which does"
    echo "not require disabling SIP."
    return 3
  fi
}

# --- Core flamegraph generation -----------------------------------------------
generate_flamegraph() {
  local friendly="$1"
  local spec bench_target group_filter
  spec="$(benchmark_spec "${friendly}")" || {
    err "Unknown benchmark: ${friendly}"
    return 4
  }
  bench_target="${spec%%:*}"
  group_filter="${spec#*:}"

  local out="${OUTPUT_DIR}/${friendly}.svg"

  info "Benchmark:  ${friendly}"
  info "Bench target: --bench ${bench_target}"
  [ -n "${group_filter}" ] && info "Group filter: ${group_filter}"
  info "Output:      ${out}"
  echo

  local os; os="$(detect_os)"

  # Build the cargo flamegraph invocation.
  #
  # `cargo flamegraph` accepts cargo-style target selection (--bench/--bin) and
  # an `--output` flag for the SVG. Everything after `--` is forwarded to the
  # profiled binary. Criterion bench binaries accept a positional filter string
  # (matching benchmark group names) plus Criterion flags like --warm-up-time.
  #
  # cargo-flamegraph automatically builds the target in release mode with debug
  # symbols, so no manual RUSTFLAGS=-g is needed.
  local -a cargo_args=(
    "flamegraph"
    "--bench" "${bench_target}"
    "--output" "${out}"
    "--"
  )

  # Append Criterion group filter (positional) so only the requested group runs.
  if [ -n "${group_filter}" ]; then
    cargo_args+=("${group_filter}")
  fi

  # Speed up Criterion: reduce sample size & warm-up for profiling runs so the
  # profiling step completes in seconds rather than minutes.
  cargo_args+=("--warm-up-time" "1" "--measurement-time" "3" "--sample-size" "10")

  case "${os}" in
    macos)
      check_sudo_macos "${friendly}" || return $?
      info "Platform: macOS (DTrace backend)"
      info "Running: cargo ${cargo_args[*]}"
      echo
      (cd "${WORKSPACE_DIR}" && cargo "${cargo_args[@]}")
      ;;
    linux)
      check_perf || return $?
      info "Platform: Linux (perf backend)"
      info "Running: cargo ${cargo_args[*]}"
      echo
      (cd "${WORKSPACE_DIR}" && cargo "${cargo_args[@]}")
      ;;
    *)
      err "Unsupported platform: $(uname -s)"
      return 1
      ;;
  esac

  if [ -f "${out}" ]; then
    ok "Flamegraph written to ${out}"
  else
    err "Expected output ${out} was not produced."
    err "Check the profiling output above for errors (e.g. dtrace/SIP, perf permissions)."
    return 1
  fi
}

# --- Argument parsing ---------------------------------------------------------
main() {
  if [ $# -lt 1 ]; then
    echo "Usage: $0 <benchmark-name|--all|--list> [-- <cargo-flamegraph args>...]"
    echo
    print_benchmarks
    exit 1
  fi

  case "$1" in
    -h|--help)
      sed -n '2,40p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    --list)
      print_benchmarks
      exit 0
      ;;
    --all)
      check_cargo_flamegraph || exit $?
      local rc=0 name
      for name in ${BENCHMARK_NAMES}; do
        echo "========================================"
        generate_flamegraph "${name}" || rc=$?
        echo
      done
      exit "${rc}"
      ;;
    -*)
      err "Unknown option: $1"
      exit 1
      ;;
    *)
      local friendly="$1"; shift
      if ! benchmark_spec "${friendly}" >/dev/null; then
        err "Unknown benchmark: ${friendly}"
        echo
        print_benchmarks
        exit 4
      fi
      check_cargo_flamegraph || exit $?
      # Remaining args (after optional `--`) are forwarded to cargo flamegraph.
      # We currently bake sensible defaults in; extra args are accepted but
      # may conflict with the ones we set. They are appended for advanced use.
      generate_flamegraph "${friendly}" "$@"
      exit $?
      ;;
  esac
}

main "$@"
