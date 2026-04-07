# ScrubbeRS

`ScrubbeRS` is a Rust-first, zero-copy (in-place) redaction engine with:

- A **stdin → stdout CLI** for shell pipelines.
- A **Rust library API**.
- Optional **Python** and **Node.js** bindings.
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

# Line-oriented streaming mode for log pipelines
tail -F app.log | ./target/release/scrubbers --stream-lines
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
use std::io::Cursor;
use scrubbers::Scrubber;

let scrubber = Scrubber::new()?;
let mut bytes = b"ghp_123456789012345678901234567890123456".to_vec();
scrubber.scrub_in_place(&mut bytes);

let mut output = Vec::new();
scrubber.scrub_lines(
    Cursor::new(b"safe\nprefix ghp_123456789012345678901234567890123456 suffix\n"),
    &mut output,
)?;
```

## Python bindings

Build the Python extension crate:

```bash
cargo build --release --manifest-path bindings/python/Cargo.toml
```

Exposed functions:

- `scrubbers.scrub_bytes(data: bytes) -> bytes`
- `scrubbers.scrub_text(data: str) -> str`
- `scrubbers.scrub_lines_bytes(data: bytes) -> bytes`
- `scrubbers.scrub_lines_text(data: str) -> str`

The `scrub_lines_*` helpers apply the library's newline-delimited streaming path over the provided input.

Example:

```python
import scrubbers

scrubbers.scrub_text("prefix ghp_123456789012345678901234567890123456 suffix")
# "prefix **************************************** suffix"

scrubbers.scrub_lines_text("safe\nprefix ghp_123456789012345678901234567890123456 suffix\n")
# "safe\nprefix **************************************** suffix\n"
```

## Node.js bindings

Build the Node extension crate:

```bash
cargo build --release --manifest-path bindings/node/Cargo.toml
```

Exposed functions:

- `scrubBuffer(buf: Buffer) -> Buffer`
- `scrubLinesBuffer(buf: Buffer) -> Buffer`

`scrubLinesBuffer(...)` applies the library's newline-delimited streaming path over the provided buffer.

Example:

```js
const { scrubBuffer, scrubLinesBuffer } = require("./scrubbers.node");

scrubBuffer(Buffer.from("prefix ghp_123456789012345678901234567890123456 suffix"))
// <Buffer 70 72 65 66 69 78 20 2a ...>

scrubLinesBuffer(
  Buffer.from("safe\nprefix ghp_123456789012345678901234567890123456 suffix\n", "utf8"),
).toString("utf8");
// "safe\nprefix **************************************** suffix\n"
```

Run binding smoke tests locally:

```bash
python3 scripts/test_bindings.py --binding all
```

Benchmark the Python binding in a logging-style path:

```bash
python3 scripts/bench_python_bindings.py
```

## TruffleHog parity workflow

TruffleHog detector coverage is tracked in `src/generated_trufflehog.rs`:

```bash
python scripts/sync_trufflehog_signatures.py
go run ./scripts/sync_trufflehog_pattern_fixtures.go
python scripts/verify_trufflehog_coverage.py
```

CI runs these commands and fails if:
- any upstream detector directory is missing from our generated signature surface, or
- generated signatures are missing when tests run.
- extracted positive fixtures are missing when tests run.

The generated TruffleHog data is tracked for parity and audit purposes, but it is not applied by default as raw redaction rules. Many upstream detectors rely on keyword gating and verifier callbacks, and running their extracted regexes directly creates false positives.

The extracted positive fixtures are also used in the Rust test suite as inline redaction cases. Each case builds literal secret fragments from the upstream positive example and asserts the scrubber preserves length while masking the matched spans in place.

## Benchmark

Run the native Criterion benchmark:

```bash
cargo bench --bench throughput -- --noplot
```

It generates a 64 MiB synthetic payload, injects multiple secret shapes, and compares:
- raw `memcpy`
- straight `std::io::copy` pass-through into a fixed buffer
- `scrubber/in_place`
- `scrubber/stream_lines`

For a quick single-number smoke run, you can still use:

```bash
cargo run --release --bin scrub-bench
```
