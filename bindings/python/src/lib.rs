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

// ---------------------------------------------------------------------------
// Streaming IO wrappers
// ---------------------------------------------------------------------------

/// A text-mode write wrapper that scrubs every `write()` call before
/// forwarding to an inner file-like object.
///
/// Implements the Python `io.TextIOBase` write protocol so it can be used
/// anywhere Python expects a writable text stream — most importantly as
/// the `stream` argument to `logging.StreamHandler`.
///
/// Example:
///     handler = logging.StreamHandler(stream=ScrubWriter(sys.stderr))
#[pyclass]
struct ScrubWriter {
    inner: PyObject,
}

#[pymethods]
impl ScrubWriter {
    #[new]
    fn new(inner: PyObject) -> Self {
        Self { inner }
    }

    /// Scrub `data` and forward the redacted text to the inner stream.
    /// Returns the *original* length so callers (including the logging
    /// framework) see the write as fully consumed.
    fn write(&self, py: Python<'_>, data: &str) -> PyResult<usize> {
        let original_len = data.len();
        let scrubbed = default_scrubber().scrubbed(data.as_bytes());
        let text = String::from_utf8(scrubbed)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        self.inner.call_method1(py, "write", (text,))?;
        Ok(original_len)
    }

    fn flush(&self, py: Python<'_>) -> PyResult<()> {
        self.inner.call_method0(py, "flush")?;
        Ok(())
    }

    fn writable(&self) -> bool {
        true
    }

    fn readable(&self) -> bool {
        false
    }

    fn seekable(&self) -> bool {
        false
    }

    fn __repr__(&self) -> String {
        "ScrubWriter(...)".to_string()
    }
}

/// A binary-mode write wrapper that scrubs every `write()` call before
/// forwarding to an inner bytes-writable file-like object.
///
/// Example:
///     raw = open("/var/log/app.log", "wb")
///     stream = ScrubStream(raw)
///     stream.write(b"token=ghp_abc123...")
#[pyclass]
struct ScrubStream {
    inner: PyObject,
}

#[pymethods]
impl ScrubStream {
    #[new]
    fn new(inner: PyObject) -> Self {
        Self { inner }
    }

    /// Scrub `data` and forward the redacted bytes to the inner stream.
    fn write<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<usize> {
        let original_len = data.len();
        let scrubbed = default_scrubber().scrubbed(data);
        let bytes = PyBytes::new_bound(py, &scrubbed);
        self.inner.call_method1(py, "write", (bytes,))?;
        Ok(original_len)
    }

    fn flush(&self, py: Python<'_>) -> PyResult<()> {
        self.inner.call_method0(py, "flush")?;
        Ok(())
    }

    fn writable(&self) -> bool {
        true
    }

    fn readable(&self) -> bool {
        false
    }

    fn seekable(&self) -> bool {
        false
    }

    fn __repr__(&self) -> String {
        "ScrubStream(...)".to_string()
    }
}

#[pymodule]
fn scrubbers(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scrub_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_text, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_lines_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_lines_text, m)?)?;
    m.add_class::<ScrubWriter>()?;
    m.add_class::<ScrubStream>()?;
    Ok(())
}
