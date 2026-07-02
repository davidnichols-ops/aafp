//! PyAgent — Python wrapper for aafp_sdk::Agent.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::exceptions::PyException;
use pyo3::types::PyBytes;
use aafp_sdk::AgentBuilder;
use aafp_identity::AgentKeypair;

/// A running AAFP agent instance.
///
/// All crypto (ML-DSA-65 key generation, signing) stays in Rust.
/// Python never touches raw key material.
#[pyclass(name = "Agent")]
pub struct PyAgent {
    pub inner: Arc<aafp_sdk::Agent>,
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
}
