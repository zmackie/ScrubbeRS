# Python binding notes

Build the wheel and sdist locally with uv:

```bash
uv build
```

On Linux, the local wheel is suitable for smoke testing but may not be acceptable to PyPI. The release workflow builds Linux wheels in a manylinux2014 container.

Smoke test the built distributions locally:

```bash
python3 scripts/test_python_package.py --artifact all
```

Build the raw extension crate directly with Cargo:

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

Install from PyPI once published:

```bash
uv add scrubbers
```
