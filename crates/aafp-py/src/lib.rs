//! Python bindings for AAFP transport via PyO3.
//!
//! This module exposes `Agent` and `AafpTransport` classes to Python,
//! allowing Python MCP clients to connect over AAFP's post-quantum QUIC transport.
//!
//! ## Segfault mitigation
//!
//! `quinn::Endpoint` (wrapped by `QuicTransport` inside `Agent`) spawns
//! background tasks on the tokio runtime. If these tasks are still alive
//! when the Python interpreter begins its final teardown, the drop order
//! between the tokio runtime, quinn's internal state, and the GIL can
//! trigger a use-after-free segfault.
//!
//! Mitigation strategy (defence in depth):
//! 1. A dedicated tokio runtime is created eagerly at module init and
//!    registered with `pyo3_async_runtimes` so all `future_into_py` calls
//!    run on it.
//! 2. `PyAgent` exposes an async `shutdown()` method that closes the QUIC
//!    endpoint, draining its background tasks before the runtime drops.
//! 3. `PyAgent::__del__` calls `transport.close()` synchronously as a
//!    last-resort safety net if the user forgot to call `shutdown()`.

use std::sync::OnceLock;

use pyo3::prelude::*;
use tokio::runtime::Runtime;

mod agent;
mod transport;

/// The dedicated tokio runtime for this extension.
///
/// Held in a `OnceLock` so it lives until process exit. `pyo3_async_runtimes`
/// is told to use this runtime via `init_with_runtime` at module init.
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Get the shared tokio runtime, creating it on first call.
pub fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create aafp_py tokio runtime")
    })
}

#[pymodule]
fn aafp_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Eagerly create the runtime and register it with pyo3_async_runtimes.
    let rt = runtime();
    // Returns Err(()) if already initialized — that's fine on reload.
    let _ = pyo3_async_runtimes::tokio::init_with_runtime(rt);

    m.add_class::<agent::PyAgent>()?;
    m.add_class::<transport::PyAafpTransport>()?;
    Ok(())
}
