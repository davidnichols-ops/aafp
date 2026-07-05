//! PyAafpTransport — Python wrapper for AafpMcpTransport.
//!
//! Provides async methods for connecting, sending, and receiving
//! JSON-RPC messages over AAFP's post-quantum QUIC transport.
//!
//! The send and receive paths use separate locks so they can run
//! concurrently (required by the MCP SDK's anyio streaming model).

use std::sync::Arc;

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyAny;
use tokio::sync::Mutex;

use crate::agent::PyAgent;

/// AAFP transport for JSON-RPC messages.
///
/// Usage:
///     transport = aafp_py.AafpTransport()
///     await transport.connect(agent, "quic://127.0.0.1:4433")
///     await transport.send({"jsonrpc": "2.0", "method": "tools/list", "id": 1})
///     response = await transport.receive()
///     await transport.close()
#[pyclass(name = "AafpTransport")]
pub struct PyAafpTransport {
    /// The full transport, used for receive and close.
    /// Send does NOT lock this — it uses `send_handle` instead, so
    /// send and receive can run concurrently.
    inner: Arc<Mutex<Option<aafp_transport_mcp::AafpMcpTransport>>>,
    /// Cloned send handle for concurrent send operations.
    /// Set after connect/accept, None before.
    send_handle: SendHandleSlot,
}

/// Type alias to simplify the complex nested send handle type.
type SendHandleSlot = Arc<Mutex<Option<Arc<Mutex<Option<aafp_transport_quic::QuicSendStream>>>>>>;

impl PyAafpTransport {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            send_handle: Arc::new(Mutex::new(None)),
        }
    }
}

#[pymethods]
impl PyAafpTransport {
    #[new]
    fn py_new() -> Self {
        Self::new()
    }

    /// Connect to an AAFP server (client side).
    fn connect<'py>(
        &self,
        py: Python<'py>,
        agent: &PyAgent,
        addr: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let send_handle_slot = self.send_handle.clone();
        let agent_inner = agent.inner.clone();
        let addr = addr.to_string();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let transport = aafp_transport_mcp::AafpMcpTransport::connect(&agent_inner, &addr)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            // Extract the send handle for concurrent send operations
            let sh = transport.send_handle();
            *send_handle_slot.lock().await = Some(sh);
            *inner.lock().await = Some(transport);
            Ok(())
        })
    }

    /// Accept an AAFP connection (server side).
    fn accept<'py>(&self, py: Python<'py>, agent: &PyAgent) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let send_handle_slot = self.send_handle.clone();
        let agent_inner = agent.inner.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let transport = aafp_transport_mcp::AafpMcpTransport::accept(&agent_inner)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            let sh = transport.send_handle();
            *send_handle_slot.lock().await = Some(sh);
            *inner.lock().await = Some(transport);
            Ok(())
        })
    }

    /// Send a JSON-RPC message as an AAFP DATA frame.
    ///
    /// This uses the send handle directly, NOT the transport mutex,
    /// so it can run concurrently with `receive()`.
    fn send<'py>(
        &self,
        py: Python<'py>,
        message: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json_value = python_to_json(message)?;
        let send_handle_slot = self.send_handle.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = send_handle_slot.lock().await;
            let send_handle = guard
                .as_ref()
                .ok_or_else(|| PyException::new_err("transport not connected"))?;
            aafp_transport_mcp::send_raw_json_on_handle(send_handle, &json_value)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(())
        })
    }

    /// Receive a JSON-RPC message from an AAFP DATA frame.
    fn receive<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let transport = guard
                .as_mut()
                .ok_or_else(|| PyException::new_err("transport not connected"))?;

            let value = transport
                .recv_raw_json()
                .await
                .ok_or_else(|| PyException::new_err("transport closed by peer"))?;

            // Convert serde_json::Value to a JSON string, return as Python string
            // The Python wrapper will parse it with json.loads
            let json_str = serde_json::to_string(&value)
                .map_err(|e| PyException::new_err(format!("JSON serialize error: {e}")))?;

            Ok(json_str)
        })
    }

    /// Close the transport gracefully.
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let send_handle_slot = self.send_handle.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Clear the send handle first
            *send_handle_slot.lock().await = None;
            // Then close the transport
            let mut guard = inner.lock().await;
            if let Some(mut transport) = guard.take() {
                transport
                    .close_raw()
                    .await
                    .map_err(|e| PyException::new_err(e.to_string()))?;
            }
            Ok(())
        })
    }

    /// The verified peer AgentId as a hex string, or None.
    #[getter]
    fn peer_agent_id(&self) -> PyResult<Option<String>> {
        let guard = self.inner.try_lock();
        if let Ok(guard) = guard {
            if let Some(transport) = guard.as_ref() {
                if let Some(id) = transport.peer_agent_id() {
                    return Ok(Some(hex::encode(id)));
                }
            }
        }
        Ok(None)
    }
}

/// Convert a Python object to serde_json::Value.
fn python_to_json(obj: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    let py = obj.py();
    let json_module = py.import("json")?;
    let json_str: String = json_module.call_method("dumps", (obj,), None)?.extract()?;
    serde_json::from_str(&json_str)
        .map_err(|e| PyException::new_err(format!("JSON parse error: {e}")))
}
