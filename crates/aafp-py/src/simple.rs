//! Python-facing simple API — wraps aafp_sdk::simple.
//!
//! This module exposes `Agent`, `Request`, `Response` classes to Python
//! that match the Rust simple API (P2.1). A Python developer can build
//! a working agent in 3 lines without reading any Rust docs.

use std::net::SocketAddr;
use std::sync::Arc;

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyTuple;

use aafp_sdk::simple::{Agent as SdkAgent, Request as SdkRequest, Response as SdkResponse};

// ─── Request ──────────────────────────────────────────────────

/// A simple request from a caller to an agent.
///
/// Usage::
///     req = Request.text("hello")
///     req = Request.data(b"\\x01\\x02\\x03")
#[pyclass(name = "Request", module = "aafp", from_py_object)]
#[derive(Clone)]
pub struct PyRequest {
    inner: SdkRequest,
}

#[pymethods]
impl PyRequest {
    /// Create a text request: Request.text("hello")
    #[staticmethod]
    #[pyo3(name = "text")]
    fn text_cls(body: &str) -> Self {
        Self {
            inner: SdkRequest::text(body),
        }
    }

    /// Create a binary data request: Request.data(b"...")
    #[staticmethod]
    #[pyo3(name = "data")]
    fn data_cls(data: Vec<u8>) -> Self {
        Self {
            inner: SdkRequest::data(data),
        }
    }

    /// The text body of the request.
    #[getter]
    fn body(&self) -> &str {
        self.inner.body()
    }

    /// The binary payload, or None.
    #[getter]
    fn payload(&self) -> Option<Vec<u8>> {
        self.inner.payload().map(|s| s.to_vec())
    }

    fn __repr__(&self) -> String {
        if let Some(data) = self.inner.payload() {
            format!("Request.data({} bytes)", data.len())
        } else {
            format!("Request.text({:?})", self.inner.body())
        }
    }
}

// ─── Response ─────────────────────────────────────────────────

/// A simple response from an agent to a caller.
///
/// Usage::
///     resp = Response.text("hello")
///     resp = Response.data(b"\\x01\\x02\\x03")
#[pyclass(name = "Response", module = "aafp", from_py_object)]
#[derive(Clone)]
pub struct PyResponse {
    inner: SdkResponse,
}

#[pymethods]
impl PyResponse {
    /// Create a text response: Response.text("hello")
    #[staticmethod]
    #[pyo3(name = "text")]
    fn text_cls(body: &str) -> Self {
        Self {
            inner: SdkResponse::text(body),
        }
    }

    /// Create a binary data response: Response.data(b"...")
    #[staticmethod]
    #[pyo3(name = "data")]
    fn data_cls(data: Vec<u8>) -> Self {
        Self {
            inner: SdkResponse::data(data),
        }
    }

    /// The text body of the response.
    #[getter]
    fn body(&self) -> &str {
        self.inner.body()
    }

    /// The binary payload, or None.
    #[getter]
    fn payload(&self) -> Option<Vec<u8>> {
        self.inner.payload().map(|s| s.to_vec())
    }

    fn __repr__(&self) -> String {
        if let Some(data) = self.inner.payload() {
            format!("Response.data({} bytes)", data.len())
        } else {
            format!("Response.text({:?})", self.inner.body())
        }
    }
}

// ─── Top-level Agent ──────────────────────────────────────────

/// Top-level entry point for the simple API.
///
/// Usage::
///     agent = await Agent.serve("echo")
///     agent = await Agent.connect()
#[pyclass(name = "SimpleAgent", module = "aafp")]
pub struct PySimpleAgent;

#[pymethods]
impl PySimpleAgent {
    /// Start serving an agent: Agent.serve(capability="echo")
    ///
    /// Returns a ServeBuilder that you can chain .capability(), .handler(), .bind() on.
    #[staticmethod]
    #[pyo3(name = "serve")]
    fn serve_cls(capability: String) -> PyServeBuilder {
        PyServeBuilder {
            capabilities: vec![capability],
            handler: None,
            bind_addr: None,
        }
    }

    /// Connect to the network: await Agent.connect()
    ///
    /// Returns a ConnectedAgent.
    #[staticmethod]
    #[pyo3(name = "connect")]
    fn connect_cls<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let agent = SdkAgent::connect()
                .connect()
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(PyConnectedAgent {
                inner: Arc::new(agent),
            })
        })
    }
}

// ─── ServeBuilder ─────────────────────────────────────────────

/// Builder for serving an agent. Chain methods then call .start().
#[pyclass(name = "ServeBuilder", module = "aafp")]
pub struct PyServeBuilder {
    capabilities: Vec<String>,
    handler: Option<Py<PyAny>>,
    bind_addr: Option<SocketAddr>,
}

#[pymethods]
impl PyServeBuilder {
    /// Add a capability: builder.capability("echo")
    fn capability(&mut self, cap: &str) {
        self.capabilities.push(cap.to_string());
    }

    /// Set the handler function: builder.handler(async def handler(req): ...)
    fn handler(&mut self, handler: Py<PyAny>) {
        self.handler = Some(handler);
    }

    /// Set the bind address: builder.bind("0.0.0.0:0")
    fn bind(&mut self, addr: &str) -> PyResult<()> {
        self.bind_addr = Some(
            addr.parse()
                .map_err(|e| PyException::new_err(format!("invalid address: {e}")))?,
        );
        Ok(())
    }

    /// Build and start the agent: await builder.start()
    fn start<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let capabilities = self.capabilities.clone();
        let handler = self.handler.as_ref().map(|h| h.clone_ref(py));
        let bind_addr = self.bind_addr;

        // Capture the current task locals (event loop) so the handler
        // can call Python async functions from a Rust tokio task.
        let task_locals = pyo3_async_runtimes::tokio::get_current_locals(py)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut builder = SdkAgent::serve();

            for cap in &capabilities {
                builder = builder.capability(cap.clone());
            }

            if let Some(addr) = bind_addr {
                builder = builder.bind(addr);
            }

            // Wrap the Python handler in a Rust async closure.
            // The closure captures:
            // - The Python callable (Py<PyAny> is Send)
            // - The TaskLocals (event loop reference, needed to schedule
            //   Python coroutines from a Rust tokio task)
            //
            // When called, it:
            // 1. Acquires the GIL to call the Python function and get a coroutine
            // 2. Converts the coroutine to a Rust future (into_future_with_locals)
            // 3. Drops the GIL and awaits the future
            // 4. Re-acquires the GIL to extract the PyResponse
            if let Some(py_handler) = handler {
                builder = builder.handler(move |req: SdkRequest| {
                    let py_handler = Python::attach(|py| py_handler.clone_ref(py));
                    let locals = task_locals.clone();
                    Box::pin(async move {
                        // Step 1: Acquire GIL, call Python handler, get coroutine
                        let coro_future = Python::attach(|py| {
                            let py_req = PyRequest { inner: req };
                            let py_req_obj = Py::new(py, py_req).map_err(|e| e.to_string())?;
                            let args =
                                PyTuple::new(py, vec![py_req_obj]).map_err(|e| e.to_string())?;
                            let coro = py_handler.call1(py, args).map_err(|e| e.to_string())?;

                            // Convert the coroutine to a Rust future using
                            // the captured task locals (event loop)
                            pyo3_async_runtimes::into_future_with_locals(
                                &locals,
                                coro.into_bound(py),
                            )
                            .map_err(|e| format!("handler is not awaitable: {e}"))
                        })?;

                        // Step 2: Await the coroutine (GIL is released)
                        let result_obj = coro_future.await.map_err(|e| e.to_string())?;

                        // Step 3: Extract the PyResponse from the result
                        Python::attach(|py| {
                            let result_ref = result_obj.bind(py);
                            let py_response: PyRef<PyResponse> = result_ref
                                .extract()
                                .map_err(|e| format!("handler must return a Response, got: {e}"))?;
                            Ok(py_response.inner.clone())
                        })
                    })
                });
            }

            let serving = builder
                .start()
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;

            Ok(PyServingAgent {
                inner: Arc::new(serving),
            })
        })
    }
}

// ─── ServingAgent ─────────────────────────────────────────────

/// A running agent that is serving requests.
#[pyclass(name = "ServingAgent", module = "aafp")]
pub struct PyServingAgent {
    inner: Arc<aafp_sdk::simple::ServingAgent>,
}

#[pymethods]
impl PyServingAgent {
    /// The agent's ID as a hex string.
    #[getter]
    fn id(&self) -> String {
        hex::encode(self.inner.id())
    }

    /// The agent's address (e.g., "quic://127.0.0.1:12345").
    #[getter]
    fn addr(&self) -> String {
        self.inner.addr().to_string()
    }

    /// Stop the serving agent.
    fn stop(&self) {
        self.inner.stop();
    }
}

// ─── ConnectedAgent ───────────────────────────────────────────

/// A connected agent that can discover and call other agents.
#[pyclass(name = "ConnectedAgent", module = "aafp")]
pub struct PyConnectedAgent {
    inner: Arc<aafp_sdk::simple::ConnectedAgent>,
}

#[pymethods]
impl PyConnectedAgent {
    /// Discover agents by capability: agent.discover("echo")
    fn discover(&self, capability: &str) -> PyDiscoveryBuilder {
        PyDiscoveryBuilder {
            inner: self.inner.clone(),
            capability: capability.to_string(),
        }
    }

    /// Call an agent at a specific address: await agent.call_at("quic://...", Request.text("hello"))
    fn call_at<'py>(
        &self,
        py: Python<'py>,
        addr: &str,
        request: &PyRequest,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let addr = addr.to_string();
        let req = request.inner.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let response = inner
                .call_at(&addr, req)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(PyResponse { inner: response })
        })
    }

    /// The agent's ID as a hex string.
    #[getter]
    fn id(&self) -> String {
        hex::encode(self.inner.id())
    }
}

// ─── DiscoveryBuilder ─────────────────────────────────────────

/// Builder for discovering and calling an agent.
#[pyclass(name = "DiscoveryBuilder", module = "aafp")]
pub struct PyDiscoveryBuilder {
    inner: Arc<aafp_sdk::simple::ConnectedAgent>,
    capability: String,
}

#[pymethods]
impl PyDiscoveryBuilder {
    /// Call the discovered agent: await builder.call(Request.text("hello"))
    fn call<'py>(&self, py: Python<'py>, request: &PyRequest) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let capability = self.capability.clone();
        let req = request.inner.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let response = inner
                .discover(&capability)
                .call(req)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(PyResponse { inner: response })
        })
    }
}
