# Python binding notes

Build with:

```bash
cargo build --release --manifest-path bindings/python/Cargo.toml
```

Smoke test locally with:

```bash
python3 scripts/test_bindings.py --binding python
```

Benchmark logging throughput with inline redaction:

```bash
python3 scripts/bench_python_bindings.py
```
