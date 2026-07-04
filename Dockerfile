# AAFP Agent Dockerfile — multi-stage build
# Stage 1: Build the agent binary
# Stage 2: Distroless runtime image

# ── Builder ──────────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifest files first (for better layer caching)
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build the CLI agent binary in release mode
RUN cargo build --release -p aafp-cli && \
    strip target/release/aafp-agent

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /build/target/release/aafp-agent /aafp-agent

# Expose QUIC transport port (UDP)
EXPOSE 4433/udp

# Environment defaults
ENV AAFP_BIND=0.0.0.0:4433
ENV RUST_LOG=warn
ENV AAFP_DATA_DIR=/data

# Volume for persistent data (keys, DHT)
VOLUME ["/data"]

# Health check — verify the agent is running
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
  CMD ["/aafp-agent", "healthcheck"]

# Run as nonroot user (distroless default)
ENTRYPOINT ["/aafp-agent"]
CMD ["serve"]
