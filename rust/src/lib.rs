
use pyo3::prelude::*;

pub mod common;
pub mod discovery;
pub mod monitoring;
pub mod network;
pub mod packets;
pub mod ports;

/// Versão da biblioteca NETSHADOW Rust.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Devolve a versão da biblioteca.
#[pyfunction]
fn get_version() -> &'static str {
    VERSION
}

/// Verifica se o núcleo Rust está disponível.
#[pyfunction]
fn health_check() -> bool {
    true
}

/// Módulo Python: netshadow_rust
#[pymodule]
fn netshadow_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_version, m)?)?;
    m.add_function(wrap_pyfunction!(health_check, m)?)?;

    m.add("__version__", VERSION)?;

    Ok(())
}
