//! PyAgent — Python wrapper for aafp_sdk::Agent.

use std::sync::{Arc, Mutex};

use aafp_identity::AgentKeypair;
use aafp_sdk::AgentBuilder;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// A running AAFP agent instance.
///
/// All crypto (ML-DSA-65 key generation, signing) stays in Rust.
/// Python never touches raw key material.
///
/// Call `await agent.shutdown()` before process exit to close the QUIC
/// endpoint cleanly and avoid a segfault during interpreter teardown.
#[pyclass(name = "Agent")]
pub struct PyAgent {
    pub inner: Arc<aafp_sdk::Agent>,
    /// Set to true once `shutdown()` has closed the QUIC endpoint.
    /// Prevents `__del__` from closing it twice.
    shutdown_done: Mutex<bool>,
}

#[pymethods]
impl PyAgent {
    /// Create a new agent bound to the given address.
    ///
    /// This is an async classmethod — must be awaited:
    ///     agent = await Agent.bind("127.0.0.1:0")
    #[staticmethod]
    fn bind<'py>(py: Python<'py>, addr: &str) -> PyResult<Bound<'py, PyAny>> {
        let parsed_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| PyException::new_err(format!("invalid address: {e}")))?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let agent = AgentBuilder::new()
                .bind(parsed_addr)
                .build()
                .await
                .map_err(|e| PyException::new_err(format!("agent build failed: {e}")))?;

            Ok(PyAgent {
                inner: Arc::new(agent),
                shutdown_done: Mutex::new(false),
            })
        })
    }

    /// Create an agent from a saved keypair file (binary format).
    ///
    /// This is an async classmethod — must be awaited:
    ///     agent = await Agent.from_keyfile("path/to/key.bin")
    #[staticmethod]
    fn from_keyfile<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyAny>> {
        let keypair_data = std::fs::read(path)
            .map_err(|e| PyException::new_err(format!("failed to read keyfile: {e}")))?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let keypair = AgentKeypair::from_bytes_full(&keypair_data)
                .map_err(|e| PyException::new_err(format!("invalid keyfile: {e}")))?;

            let agent = AgentBuilder::new()
                .with_keypair(keypair)
                .bind("127.0.0.1:0".parse().unwrap())
                .build()
                .await
                .map_err(|e| PyException::new_err(format!("agent build failed: {e}")))?;

            Ok(PyAgent {
                inner: Arc::new(agent),
                shutdown_done: Mutex::new(false),
            })
        })
    }

    /// Save the agent's keypair to a file (binary format).
    fn save_keyfile(&self, path: &str) -> PyResult<()> {
        std::fs::write(path, self.inner.keypair.to_bytes())
            .map_err(|e| PyException::new_err(format!("failed to write keyfile: {e}")))
    }

    /// The agent's ID as a hex string (SHA-256 of public key).
    #[getter]
    fn agent_id(&self) -> String {
        hex::encode(self.inner.agent_id)
    }

    /// The agent's multiaddr (e.g., "quic://127.0.0.1:12345").
    #[getter]
    fn multiaddr(&self) -> PyResult<String> {
        self.inner
            .multiaddr()
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// The agent's public key as raw bytes.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.keypair.public_key)
    }

    /// Close the QUIC endpoint and drain background tasks.
    ///
    /// Call this before process exit to avoid a segfault during
    /// interpreter teardown. After `shutdown()`, the agent can no
    /// longer accept or dial new connections.
    ///
    /// This is idempotent — calling it twice is safe.
    fn shutdown<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let already_done = {
            let mut guard = self.shutdown_done.lock().unwrap();
            let was = *guard;
            *guard = true;
            was
        };

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if !already_done {
                inner.transport.close();
                // Wait for quinn's background tasks to drain. Without this,
                // the tokio runtime drops while quinn still has pending work,
                // causing a use-after-free segfault during interpreter teardown.
                inner.transport.wait_idle().await;
            }
            Ok(())
        })
    }

    /// Synchronously close the QUIC endpoint (best-effort, non-blocking).
    ///
    /// Unlike `shutdown()`, this does NOT wait for quinn's background tasks
    /// to drain. It is intended as a safety net for when the event loop is
    /// already closed and `await shutdown()` cannot be called. For clean
    /// shutdown, prefer `await agent.shutdown()`.
    ///
    /// This is idempotent — calling it twice is safe.
    fn close(&self) {
        let mut guard = self.shutdown_done.lock().unwrap();
        if !*guard {
            self.inner.transport.close();
            *guard = true;
        }
    }

    /// Safety net: close the QUIC endpoint if `shutdown()` was not called.
    ///
    /// This runs during garbage collection / interpreter teardown.
    /// It calls `transport.close()` synchronously (non-blocking) to
    /// signal quinn's background tasks to stop. This alone may not
    /// prevent a segfault if the tasks don't drain in time — users
    /// should call `await agent.shutdown()` for a clean exit.
    fn __del__(&self) {
        let mut guard = self.shutdown_done.lock().unwrap();
        if !*guard {
            // Best-effort: close() just sends a close packet, it does not block.
            self.inner.transport.close();
            *guard = true;
        }
    }
}
