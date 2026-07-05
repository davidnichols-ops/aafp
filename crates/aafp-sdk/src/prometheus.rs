//! Prometheus metrics exporter (P2.6).
//!
//! Exposes agent metrics in Prometheus text format on an HTTP endpoint.
//! Uses a minimal HTTP server built on tokio::net::TcpListener — no
//! extra dependencies required.
//!
//! ## Usage
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use aafp_sdk::metrics::AgentMetrics;
//! # use aafp_sdk::prometheus::PrometheusExporter;
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let metrics = AgentMetrics::new();
//! let exporter = PrometheusExporter::new(metrics, "abc123".to_string());
//! exporter.serve("0.0.0.0:9090".parse()?).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Endpoint: `GET /metrics` — returns Prometheus-format text.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::metrics::AgentMetrics;

/// Prometheus metrics exporter.
///
/// Serves agent metrics in Prometheus text format on a configurable
/// HTTP endpoint. Only handles `GET /metrics`.
pub struct PrometheusExporter {
    metrics: Arc<AgentMetrics>,
    agent_id: String,
}

impl PrometheusExporter {
    /// Create a new exporter.
    ///
    /// # Arguments
    /// * `metrics` — The agent's metrics counters
    /// * `agent_id` — Agent ID (hex string) used as a Prometheus label
    pub fn new(metrics: Arc<AgentMetrics>, agent_id: String) -> Self {
        Self { metrics, agent_id }
    }

    /// Start serving Prometheus metrics on the given HTTP port.
    ///
    /// Endpoint: `http://{addr}/metrics`
    ///
    /// This function runs forever (until the process exits). It should
    /// be spawned with `tokio::spawn`.
    pub async fn serve(self, addr: SocketAddr) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("Prometheus exporter listening on http://{addr}/metrics");

        loop {
            match listener.accept().await {
                Ok((mut socket, peer_addr)) => {
                    let exporter = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = exporter.handle_request(&mut socket).await {
                            tracing::debug!("metrics request from {peer_addr} failed: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("accept error in prometheus exporter: {e}");
                }
            }
        }
    }

    /// Handle a single HTTP request.
    async fn handle_request(
        &self,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<(), std::io::Error> {
        // Read the HTTP request (just need the first line)
        let mut buf = vec![0u8; 1024];
        let _ = socket.read(&mut buf).await;

        // Parse the request line
        let request = String::from_utf8_lossy(&buf);
        let request_line = request.lines().next().unwrap_or("");

        // Only handle GET /metrics
        if request_line.starts_with("GET /metrics") {
            let body = self.render();
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await?;
        } else {
            // 404 for anything else
            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            socket.write_all(response.as_bytes()).await?;
        }

        Ok(())
    }

    /// Generate Prometheus-format text for the current metrics.
    pub fn render(&self) -> String {
        let snap = self.metrics.snapshot();
        let id = &self.agent_id;

        let mut out = String::with_capacity(2048);

        // Helper to append a metric
        macro_rules! metric {
            ($name:expr, $help:expr, $type:expr, $value:expr) => {{
                out.push_str(&format!("# HELP {} {}\n", $name, $help));
                out.push_str(&format!("# TYPE {} {}\n", $name, $type));
                out.push_str(&format!("{}{{agent_id=\"{}\"}} {}\n", $name, id, $value));
            }};
        }

        metric!(
            "aafp_connections_active",
            "Current active connections",
            "gauge",
            snap.connections_active
        );
        metric!(
            "aafp_connections_total",
            "Total connections established",
            "counter",
            snap.connections_total
        );
        metric!(
            "aafp_messages_sent_total",
            "Total messages sent",
            "counter",
            snap.messages_sent
        );
        metric!(
            "aafp_messages_received_total",
            "Total messages received",
            "counter",
            snap.messages_received
        );
        metric!(
            "aafp_bytes_sent_total",
            "Total bytes sent",
            "counter",
            snap.bytes_sent
        );
        metric!(
            "aafp_bytes_received_total",
            "Total bytes received",
            "counter",
            snap.bytes_received
        );
        metric!(
            "aafp_handshakes_completed_total",
            "Total handshakes completed",
            "counter",
            snap.handshakes_completed
        );
        metric!(
            "aafp_handshakes_failed_total",
            "Total handshakes failed",
            "counter",
            snap.handshakes_failed
        );
        metric!(
            "aafp_dht_records",
            "DHT records stored",
            "gauge",
            snap.dht_records
        );
        metric!(
            "aafp_relay_connections",
            "Active relay connections",
            "gauge",
            snap.relay_connections
        );
        metric!(
            "aafp_messages_failed_total",
            "Total messages that failed",
            "counter",
            snap.messages_failed
        );
        metric!(
            "aafp_uptime_seconds",
            "Agent uptime in seconds",
            "gauge",
            snap.uptime_seconds
        );

        out
    }
}

impl Clone for PrometheusExporter {
    fn clone(&self) -> Self {
        Self {
            metrics: self.metrics.clone(),
            agent_id: self.agent_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_format() {
        let metrics = AgentMetrics::new();
        metrics.record_connection();
        metrics.record_sent(1024);
        metrics.record_received(512);
        metrics.record_handshake();

        let exporter = PrometheusExporter::new(metrics, "abc123".to_string());
        let output = exporter.render();

        // Check that all expected metrics are present
        assert!(output.contains("# HELP aafp_connections_active"));
        assert!(output.contains("# TYPE aafp_connections_active gauge"));
        assert!(output.contains("aafp_connections_active{agent_id=\"abc123\"} 1"));

        assert!(output.contains("# HELP aafp_messages_sent_total"));
        assert!(output.contains("# TYPE aafp_messages_sent_total counter"));
        assert!(output.contains("aafp_messages_sent_total{agent_id=\"abc123\"} 1"));

        assert!(output.contains("# HELP aafp_bytes_sent_total"));
        assert!(output.contains("aafp_bytes_sent_total{agent_id=\"abc123\"} 1024"));

        assert!(output.contains("# HELP aafp_handshakes_completed_total"));
        assert!(output.contains("aafp_handshakes_completed_total{agent_id=\"abc123\"} 1"));

        // Check uptime is present (value may vary)
        assert!(output.contains("# HELP aafp_uptime_seconds"));
        assert!(output.contains("# TYPE aafp_uptime_seconds gauge"));
    }

    #[test]
    fn test_render_empty_metrics() {
        let metrics = AgentMetrics::new();
        let exporter = PrometheusExporter::new(metrics, "empty".to_string());
        let output = exporter.render();

        // All metrics should be present with value 0
        assert!(output.contains("aafp_connections_active{agent_id=\"empty\"} 0"));
        assert!(output.contains("aafp_messages_sent_total{agent_id=\"empty\"} 0"));
        assert!(output.contains("aafp_handshakes_failed_total{agent_id=\"empty\"} 0"));
    }

    #[tokio::test]
    async fn test_http_endpoint() {
        let metrics = AgentMetrics::new();
        metrics.record_connection();
        metrics.record_sent(100);

        let exporter = PrometheusExporter::new(metrics, "test123".to_string());

        // Start the exporter on a random port
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        // Spawn the server loop manually (just accept one connection)
        let exporter_clone = exporter.clone();
        let server_handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            exporter_clone.handle_request(&mut socket).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and send a GET /metrics request
        let mut stream = tokio::net::TcpStream::connect(actual_addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        // Read the response
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);

        // Verify HTTP response
        assert!(response_str.starts_with("HTTP/1.1 200 OK"));
        assert!(response_str.contains("Content-Type: text/plain"));
        assert!(response_str.contains("aafp_connections_active{agent_id=\"test123\"} 1"));
        assert!(response_str.contains("aafp_messages_sent_total{agent_id=\"test123\"} 1"));

        // Wait for server to finish
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_http_404_for_unknown_path() {
        let metrics = AgentMetrics::new();
        let exporter = PrometheusExporter::new(metrics, "test".to_string());

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let exporter_clone = exporter.clone();
        let server_handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            exporter_clone.handle_request(&mut socket).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = tokio::net::TcpStream::connect(actual_addr).await.unwrap();
        stream
            .write_all(b"GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);

        assert!(response_str.starts_with("HTTP/1.1 404 Not Found"));

        server_handle.await.unwrap();
    }
}
