# WAN Testing Guide

This document describes how to run AAFP WAN (wide-area network) tests
between two machines, as well as localhost simulation for single-machine
testing.

## Overview

The WAN test infrastructure consists of:

- **`scripts/wan-test-server.sh`** — starts an AAFP server agent
- **`scripts/wan-test-client.sh`** — connects to a remote server and runs tests
- **`scripts/wan-test-setup.sh`** — runs a complete localhost test (server + client)
- **`tests/wan_test.rs`** — Rust integration test (configurable via env vars)
- **`examples/wan_test_server.rs`** — standalone server binary
- **`examples/wan_test_client.rs`** — standalone client binary

## Two-Machine Setup

### Machine A (Server)

The server must have a public IP or a port-forwarded address. QUIC uses
UDP, so ensure the firewall allows UDP traffic on the chosen port.

```bash
# On Machine A (server):
cd implementations/rust
./scripts/wan-test-server.sh 4433

# Or with a specific bind address:
AAFP_SERVER_BIND=0.0.0.0 AAFP_SERVER_PORT=4433 ./scripts/wan-test-server.sh
```

The server prints its address once ready:
```
Server listening on: quic://0.0.0.0:4433
```

### Machine B (Client)

```bash
# On Machine B (client):
cd implementations/rust
./scripts/wan-test-client.sh quic://<machine-a-ip>:4433 ping

# With options:
AAFP_MSG_COUNT=1000 AAFP_MSG_SIZE=1024 \
AAFP_CONGESTION=bbr \
./scripts/wan-test-client.sh quic://<machine-a-ip>:4433 ping
```

### Test Modes

| Mode        | Description                                    |
|-------------|------------------------------------------------|
| `ping`      | 1000 round-trips, measure p50/p90/p99 latency  |
| `echo`      | Same as ping (server echoes back)              |
| `stream`    | 1000 one-way messages, measure throughput      |
| `handshake` | Measure QUIC + TLS handshake time              |
| `discovery` | Basic connectivity + round-trip check          |
| `migration` | Basic connectivity (full migration in O6)      |

### Congestion Controllers

Set `AAFP_CONGESTION` to test different controllers:

| Value     | Controller | Use Case                        |
|-----------|------------|---------------------------------|
| `cubic`   | Cubic      | Default, TCP-friendly            |
| `bbr`     | BBR        | Low-latency RPC, handles loss    |
| `newreno` | NewReno    | Simple, conservative             |

## Localhost Simulation (Single Machine)

For development and CI, all tests can run on localhost:

```bash
# Run a complete test (server + client):
./scripts/wan-test-setup.sh ping 1000 1024

# Or run the Rust integration tests:
cargo test --test wan_test -- --nocapture

# Run the remote test with a local server:
# Terminal 1: ./scripts/wan-test-server.sh
# Terminal 2: AAFP_REMOTE_ADDR=quic://127.0.0.1:4433 \
#             cargo test --test wan_test -- --nocapture --ignored
```

## Output Format

The client outputs JSON results to stdout and optionally to a file:

```json
{
  "test_mode": "ping",
  "remote_addr": "quic://192.168.1.100:4433",
  "timestamp": "1751545600",
  "congestion": "cubic",
  "msg_count": 1000,
  "msg_size": 1024,
  "success": true,
  "error": null,
  "latency": {
    "count": 1000,
    "min_us": 150.2,
    "p50_us": 180.5,
    "p90_us": 220.1,
    "p99_us": 350.8,
    "p999_us": 500.3,
    "max_us": 1200.0,
    "mean_us": 190.2
  },
  "throughput_msgs_per_sec": null,
  "throughput_mbps": null,
  "handshake_time_ms": null,
  "duration_secs": 0.19
}
```

Results are written to `test-results/interop/wan-<mode>-<timestamp>.json`.

## Troubleshooting

### Connection Refused / Timeout

- **Firewall blocking UDP:** QUIC uses UDP. Ensure the firewall on the
  server allows inbound UDP on the chosen port.
  ```bash
  # Linux (ufw):
  sudo ufw allow 4433/udp

  # macOS: System Settings > Network > Firewall > Allow
  ```
- **Wrong address:** Verify the server's public IP. Use `curl ifconfig.me`
  on the server to check.
- **NAT:** If the server is behind NAT, configure port forwarding for
  UDP port 4433 to the server's local IP.

### High Latency / Packet Loss

- **Expected on WAN:** WAN latency = localhost + network RTT. A 50ms RTT
  network adds ~50ms to each round-trip.
- **Use toxiproxy for simulation:** See O3 (adverse conditions) for
  simulating packet loss and latency with toxiproxy.

### QUIC-Specific Issues

- **UDP blocking:** Some corporate/firewall environments block all UDP
  traffic. QUIC cannot work in these environments. Use a VPN or
  different network.
- **MTU issues:** If large messages fail, the network may have a smaller
  MTU. QUIC handles fragmentation, but very large messages may time out.
- **Idle timeout:** Default idle timeout is 30s. For high-latency links,
  increase it via `QuicConfig::max_idle_timeout`.

## Network Condition Simulation

### toxiproxy (userspace, no root)

```bash
# Install:
brew install toxiproxy   # macOS
# or: apt install toxiproxy  # Linux

# Create a proxy:
toxiproxy-cli create aafp_proxy -l 127.0.0.1:4434 -u 127.0.0.1:4433

# Add 100ms latency:
toxiproxy-cli toxic add aafp_proxy -t latency -n latency_100 -a 100

# Add 5% packet loss (via timeout toxic):
toxiproxy-cli toxic add aafp_proxy -t timeout -n loss_5 -a 0 -t 5000

# Test through the proxy:
./scripts/wan-test-client.sh quic://127.0.0.1:4434 ping

# Clean up:
toxiproxy-cli delete aafp_proxy
```

### Linux tc (requires root)

```bash
# Add 100ms latency + 5% loss:
sudo tc qdisc add dev eth0 root netem delay 100ms loss 5%

# Remove:
sudo tc qdisc del dev eth0 root
```

### macOS Network Link Conditioner

1. Install: Xcode > Open Developer Tool > More Developer Tools >
   Additional Tools for Xcode > Network Link Conditioner
2. Enable: System Preferences > Network Link Conditioner
3. Choose preset: 3G, Edge, Very Bad Network, or Custom (set loss% and delay)

## Expected Results

| Metric      | Localhost | LAN (~1ms) | WAN (~50ms) | Adverse (5% loss) |
|-------------|-----------|------------|-------------|-------------------|
| Round-trip  | ~41µs     | ~2ms       | ~100ms      | ~200ms (est)      |
| Throughput  | ~776K/s   | ~100K/s    | ~10K/s      | ~5K/s (est)       |
| Handshake   | ~240µs    | ~5ms       | ~200ms      | ~500ms (est)      |
