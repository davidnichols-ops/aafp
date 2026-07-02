//! Python bindings for AAFP transport via PyO3.
//!
//! This module exposes `Agent` and `AafpTransport` classes to Python,
//! allowing Python MCP clients to connect over AAFP's post-quantum QUIC transport.

use pyo3::prelude::*;

mod agent;
mod transport;

#[pymodule]
fn aafp_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<agent::PyAgent>()?;
    m.add_class::<transport::PyAafpTransport>()?;
    Ok(())
}
