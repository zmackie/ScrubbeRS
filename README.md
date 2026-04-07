# ScrubbeRS

`ScrubbeRS` is a Rust-first, zero-copy (in-place) redaction engine with:

- A **stdin → stdout CLI** for shell pipelines.
- A **Rust library API**.
- Optional **Python** and **Node.js** bindings (feature-gated).
- Built-in high-confidence detector signatures for direct redaction.
- Optional `.scrub` signature files for custom org-specific patterns.

## Why this is fast

- Redaction happens **in place** (`&mut [u8]`) with byte-mask filling.
- Literal signatures are matched with **Aho-Corasick** (single-pass multi-pattern automaton).
- Regex signatures use compiled `regex::bytes::Regex` and run against raw bytes.
- Release profile is tuned (`lto=fat`, `codegen-units=1`, `panic=abort`).

## CLI usage

```bash
# Build release binary
cargo build --release

# Pipe mode (stdin -> stdout)
cat app.log | ./target/release/scrubbers > redacted.log

# With custom signatures
cat app.log | ./target/release/scrubbers --scrub-file .scrub > redacted.log

# Custom mask byte
cat app.log | ./target/release/scrubbers --mask "#" > redacted.log
```

## `.scrub` format

Each non-empty, non-comment line is either:

1. `name=regex_or_literal`
2. `regex_or_literal` (auto-named)

Example:

```text
# redact internal session tokens
session_token=sess_[A-Za-z0-9]{32}

# redact literal phrase
MY_INTERNAL_SECRET_PREFIX
```

## Rust API

```rust
use scrubbers::Scrubber;

let scrubber = Scrubber::new()?;
let mut bytes = b"ghp_123456789012345678901234567890123456".to_vec();
scrubber.scrub_in_place(&mut bytes);
```

## Python bindings

Enable `python` feature and build as an extension module (for example with `maturin`):

```bash
cargo build --release --features python
```

Exposed function:

- `scrubbers.scrub_bytes(data: bytes) -> bytes`

## Node.js bindings

Enable `node` feature and build with your preferred N-API workflow:

```bash
cargo build --release --features node
```

Exposed function:

- `scrub_buffer(buf: Buffer) -> Buffer`

## TruffleHog parity workflow

TruffleHog detector coverage is tracked in `src/generated_trufflehog.rs`:

```bash
python scripts/sync_trufflehog_signatures.py
python scripts/verify_trufflehog_coverage.py
```

CI runs these commands and fails if:
- any upstream detector directory is missing from our generated signature surface, or
- generated signatures are missing when tests run.

The generated TruffleHog data is tracked for parity and audit purposes, but it is not applied by default as raw redaction rules. Many upstream detectors rely on keyword gating and verifier callbacks, and running their extracted regexes directly creates false positives.

## Benchmark

Run the native Criterion benchmark:

```bash
cargo bench --bench throughput -- --noplot
```

It generates a 64 MiB synthetic payload, injects multiple secret shapes, and compares:
- raw `memcpy`
- straight `std::io::copy` pass-through into a fixed buffer
- `scrubber/in_place`

For a quick single-number smoke run, you can still use:

```bash
cargo run --release --bin scrub-bench
```
