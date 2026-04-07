//! scrubbers: fast in-place secret redaction primitives.

mod signatures;

use aho_corasick::AhoCorasick;
use regex::bytes::Regex;
use std::fs;
use std::path::Path;
use thiserror::Error;

pub use signatures::{default_signatures, trufflehog_source_commit};

#[derive(Debug, Error)]
pub enum ScrubError {
    #[error("invalid signature regex '{name}': {reason}")]
    InvalidRegex { name: String, reason: String },
    #[error("failed to read signature file: {0}")]
    SignatureIo(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct SignatureSpec {
    pub name: String,
    pub pattern: String,
}

#[derive(Debug)]
pub struct Scrubber {
    literal_matcher: AhoCorasick,
    literal_patterns: Vec<Vec<u8>>,
    regexes: Vec<(String, Regex)>,
    mask_byte: u8,
}

impl Scrubber {
    pub fn new() -> Result<Self, ScrubError> {
        Self::with_signatures(default_signatures(), b'*')
    }

    pub fn with_signatures(specs: Vec<SignatureSpec>, mask_byte: u8) -> Result<Self, ScrubError> {
        let mut literal_patterns: Vec<Vec<u8>> = Vec::new();
        let mut regexes = Vec::new();

        for spec in specs {
            if is_plain_literal(&spec.pattern) {
                literal_patterns.push(spec.pattern.into_bytes());
            } else {
                let regex = Regex::new(&spec.pattern).map_err(|e| ScrubError::InvalidRegex {
                    name: spec.name.clone(),
                    reason: e.to_string(),
                })?;
                regexes.push((spec.name, regex));
            }
        }

        let literal_matcher = if literal_patterns.is_empty() {
            AhoCorasick::new(["__no_literal_signatures__"]).expect("valid fallback automaton")
        } else {
            AhoCorasick::new(
                literal_patterns
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).to_string())
                    .collect::<Vec<_>>(),
            )
            .expect("valid automaton")
        };

        Ok(Self {
            literal_matcher,
            literal_patterns,
            regexes,
            mask_byte,
        })
    }

    /// In-place scrub: no output buffer allocation, only range bookkeeping.
    pub fn scrub_in_place(&self, input: &mut [u8]) {
        let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(64);

        if !self.literal_patterns.is_empty() {
            for m in self.literal_matcher.find_iter(input) {
                ranges.push((m.start(), m.end()));
            }
        }

        for (_, re) in &self.regexes {
            for m in re.find_iter(input) {
                ranges.push((m.start(), m.end()));
            }
        }

        if ranges.is_empty() {
            return;
        }

        ranges.sort_unstable_by_key(|(start, _)| *start);
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());

        for (start, end) in ranges {
            match merged.last_mut() {
                Some((_, prev_end)) if start <= *prev_end => {
                    if end > *prev_end {
                        *prev_end = end;
                    }
                }
                _ => merged.push((start, end)),
            }
        }

        for (start, end) in merged {
            input[start..end].fill(self.mask_byte);
        }
    }

    pub fn scrubbed(&self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        self.scrub_in_place(&mut out);
        out
    }
}

fn is_plain_literal(pattern: &str) -> bool {
    !pattern.bytes().any(|b| {
        matches!(
            b as char,
            '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' | '^' | '$' | '|'
        )
    })
}

pub fn parse_scrub_file(path: &Path) -> Result<Vec<SignatureSpec>, ScrubError> {
    let content = fs::read_to_string(path)?;
    let mut specs = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (name, pattern) = if let Some((name, pattern)) = line.split_once('=') {
            (name.trim().to_string(), pattern.trim().to_string())
        } else {
            (format!("custom_line_{}", idx + 1), line.to_string())
        };

        specs.push(SignatureSpec { name, pattern });
    }

    Ok(specs)
}

#[cfg(feature = "python")]
mod python_bindings {
    use super::*;
    use pyo3::prelude::*;
    use pyo3::types::PyBytes;

    #[pyfunction]
    fn scrub_bytes(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
        let scrubber =
            Scrubber::new().map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let out = scrubber.scrubbed(data);
        Ok(PyBytes::new_bound(py, &out).into())
    }

    #[pymodule]
    fn scrubbers(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(scrub_bytes, m)?)?;
        Ok(())
    }
}

#[cfg(feature = "node")]
mod node_bindings {
    use super::*;
    use napi::bindgen_prelude::Buffer;
    use napi_derive::napi;

    #[napi]
    pub fn scrub_buffer(buf: Buffer) -> napi::Result<Buffer> {
        let scrubber = Scrubber::new().map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let out = scrubber.scrubbed(&buf);
        Ok(out.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_patterns() {
        let scrubber = Scrubber::new().unwrap();
        let mut payload =
            b"token=ghp_123456789012345678901234567890123456 aws=AKIA1234567890ABCD".to_vec();
        scrubber.scrub_in_place(&mut payload);
        let s = String::from_utf8(payload).unwrap();
        assert!(!s.contains("ghp_"));
        assert!(!s.contains("AKIA"));
    }

    #[test]
    fn custom_scrub_file_works() {
        let specs = vec![SignatureSpec {
            name: "foo".into(),
            pattern: "foo-secret".into(),
        }];
        let scrubber = Scrubber::with_signatures(specs, b'#').unwrap();
        let out = scrubber.scrubbed(b"hello foo-secret world");
        assert_eq!(String::from_utf8(out).unwrap(), "hello ########## world");
    }
}
