//! scrubbers: fast in-place secret redaction primitives.

mod signatures;

use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use regex::bytes::{Regex, RegexBuilder};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use thiserror::Error;

pub use signatures::{
    default_signatures, trufflehog_detector_signatures, trufflehog_generated_detector_count,
    trufflehog_generated_signature_count, trufflehog_source_commit,
};

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
    literal_matcher: Option<AhoCorasick>,
    regexes: Vec<Regex>,
    mask_byte: u8,
}

impl Scrubber {
    pub fn new() -> Result<Self, ScrubError> {
        Self::build(default_signatures(), b'*')
    }

    pub fn with_signatures(specs: Vec<SignatureSpec>, mask_byte: u8) -> Result<Self, ScrubError> {
        Self::build(specs, mask_byte)
    }

    fn build(specs: Vec<SignatureSpec>, mask_byte: u8) -> Result<Self, ScrubError> {
        let mut literal_patterns: Vec<Vec<u8>> = Vec::new();
        let mut regexes = Vec::new();

        for spec in specs {
            if is_plain_literal(&spec.pattern) {
                literal_patterns.push(spec.pattern.into_bytes());
            } else {
                match RegexBuilder::new(&spec.pattern).unicode(false).build() {
                    Ok(regex) => regexes.push(regex),
                    // Generated TruffleHog patterns may target upstream regex engines
                    // with syntax Rust's regex crate does not support. Drop only those
                    // defaults so custom/user-provided signatures still fail loudly.
                    Err(_) if spec.name.starts_with("trufflehog_") => {
                        continue;
                    }
                    Err(e) => {
                        return Err(ScrubError::InvalidRegex {
                            name: spec.name.clone(),
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        let literal_matcher = if literal_patterns.is_empty() {
            None
        } else {
            Some(AhoCorasick::new(literal_patterns).expect("valid automaton"))
        };

        Ok(Self {
            literal_matcher,
            regexes,
            mask_byte,
        })
    }

    /// In-place scrub: no output buffer allocation, only range bookkeeping.
    pub fn scrub_in_place(&self, input: &mut [u8]) {
        let haystack: &[u8] = input;
        let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(64);

        if let Some(matcher) = &self.literal_matcher {
            for m in matcher.find_iter(haystack) {
                ranges.push((m.start(), m.end()));
            }
        }

        if should_parallelize_regex_scan(haystack.len(), self.regexes.len()) {
            let mut regex_ranges: Vec<(usize, usize)> = self
                .regexes
                .par_iter()
                .flat_map_iter(|re| re.find_iter(haystack).map(|m| (m.start(), m.end())))
                .collect();
            ranges.append(&mut regex_ranges);
        } else {
            for re in &self.regexes {
                for m in re.find_iter(haystack) {
                    ranges.push((m.start(), m.end()));
                }
            }
        }

        if ranges.is_empty() {
            return;
        }

        ranges.sort_unstable();

        let mut current = ranges[0];
        for &(start, end) in &ranges[1..] {
            if start <= current.1 {
                if end > current.1 {
                    current.1 = end;
                }
            } else {
                input[current.0..current.1].fill(self.mask_byte);
                current = (start, end);
            }
        }
        input[current.0..current.1].fill(self.mask_byte);
    }

    pub fn scrubbed(&self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        self.scrub_in_place(&mut out);
        out
    }

    /// Line-oriented streaming scrub for log-style inputs.
    ///
    /// This keeps memory bounded, but only detects secrets contained within a
    /// single newline-delimited record.
    pub fn scrub_lines<R: BufRead, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> io::Result<()> {
        let mut line = Vec::with_capacity(8 * 1024);
        loop {
            line.clear();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                return Ok(());
            }

            self.scrub_in_place(&mut line);
            writer.write_all(&line)?;
        }
    }
}

fn should_parallelize_regex_scan(haystack_len: usize, regex_count: usize) -> bool {
    haystack_len >= 1024 * 1024 && regex_count >= 4
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_patterns() {
        let scrubber = Scrubber::new().unwrap();
        let mut payload =
            b"token=ghp_123456789012345678901234567890123456 aws=AKIA1234567890ABCDEF".to_vec();
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

    #[test]
    fn default_signatures_build_via_with_signatures() {
        Scrubber::with_signatures(default_signatures(), b'*').unwrap();
    }

    #[test]
    fn invalid_custom_regex_still_errors() {
        let specs = vec![SignatureSpec {
            name: "broken".into(),
            pattern: "{".into(),
        }];
        let err = Scrubber::with_signatures(specs, b'*').unwrap_err();
        assert!(matches!(err, ScrubError::InvalidRegex { .. }));
    }

    #[test]
    fn scrub_lines_redacts_line_delimited_input() {
        let scrubber = Scrubber::new().unwrap();
        let input = b"safe\nprefix ghp_123456789012345678901234567890123456 suffix\n";
        let mut output = Vec::new();
        scrubber
            .scrub_lines(std::io::Cursor::new(input), &mut output)
            .unwrap();
        assert_eq!(
            output,
            b"safe\nprefix **************************************** suffix\n"
        );
    }
}
