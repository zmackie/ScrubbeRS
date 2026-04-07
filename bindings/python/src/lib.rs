use pyo3::prelude::*;
use pyo3::types::PyBytes;
use scrubbers_core::Scrubber;
use std::io::Cursor;
use std::sync::OnceLock;

fn default_scrubber() -> &'static Scrubber {
    static SCRUBBER: OnceLock<Scrubber> = OnceLock::new();
    SCRUBBER.get_or_init(|| Scrubber::new().expect("default scrubber should initialize"))
}

fn scrub_lines_bytes_inner(data: &[u8]) -> PyResult<Vec<u8>> {
    let mut output = Vec::with_capacity(data.len());
    default_scrubber()
        .scrub_lines(Cursor::new(data), &mut output)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?;
    Ok(output)
}

#[pyfunction]
fn scrub_bytes(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let out = default_scrubber().scrubbed(data);
    Ok(PyBytes::new_bound(py, &out).into())
}

#[pyfunction]
fn scrub_text(data: &str) -> PyResult<String> {
    let out = default_scrubber().scrubbed(data.as_bytes());
    String::from_utf8(out).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn scrub_lines_bytes(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let out = scrub_lines_bytes_inner(data)?;
    Ok(PyBytes::new_bound(py, &out).into())
}

#[pyfunction]
fn scrub_lines_text(data: &str) -> PyResult<String> {
    let out = scrub_lines_bytes_inner(data.as_bytes())?;
    String::from_utf8(out).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pymodule]
fn scrubbers(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scrub_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_text, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_lines_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_lines_text, m)?)?;
    Ok(())
}
