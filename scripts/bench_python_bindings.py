#!/usr/bin/env python3
import argparse
import importlib
import json
import logging
import shutil
import statistics
import sys
import sysconfig
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from test_bindings import TARGET_ROOT, build_python, dylib_extension


ROOT = Path(__file__).resolve().parents[1]


def log(level: str, event: str, **fields: object) -> None:
    payload = {"level": level, "event": event}
    payload.update(fields)
    print(json.dumps(payload))


class CountingStream:
    def __init__(self) -> None:
        self.bytes_written = 0
        self.write_calls = 0

    def reset(self) -> None:
        self.bytes_written = 0
        self.write_calls = 0

    def write(self, text: str) -> int:
        encoded = text.encode("utf-8")
        self.bytes_written += len(encoded)
        self.write_calls += 1
        return len(text)

    def flush(self) -> None:
        return None


class PlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


class RedactingFormatter(logging.Formatter):
    def __init__(self, scrubbers_module: object) -> None:
        super().__init__()
        self.scrubbers = scrubbers_module

    def format(self, record: logging.LogRecord) -> str:
        return self.scrubbers.scrub_text(record.getMessage())


def make_logger(name: str, formatter: logging.Formatter, sink: CountingStream) -> logging.Logger:
    logger = logging.Logger(name=name, level=logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler(sink)
    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger


def build_message(target_bytes: int) -> str:
    prefix = (
        "ts=2026-04-07T12:00:00Z level=INFO service=api "
        "request_id=req-123456 user=alice token=ghp_123456789012345678901234567890123456 "
        "msg=python binding benchmark "
    )
    if len(prefix) >= target_bytes:
        return prefix
    return prefix + ("x" * (target_bytes - len(prefix)))


def summarize_case(name: str, samples: list[dict[str, float]]) -> None:
    median_secs = statistics.median(sample["seconds"] for sample in samples)
    median_lines_per_sec = statistics.median(sample["lines_per_sec"] for sample in samples)
    median_mib_per_sec = statistics.median(sample["mib_per_sec"] for sample in samples)
    median_ns_per_line = statistics.median(sample["ns_per_line"] for sample in samples)
    log(
        "info",
        "summary",
        case=name,
        median_seconds=round(median_secs, 6),
        median_lines_per_sec=round(median_lines_per_sec, 2),
        median_mib_per_sec=round(median_mib_per_sec, 2),
        median_ns_per_line=round(median_ns_per_line, 1),
    )


def benchmark_case(
    name: str,
    iterations: int,
    rounds: int,
    bytes_per_line: int,
    action,
) -> None:
    action()
    samples = []
    for round_idx in range(1, rounds + 1):
        start = time.perf_counter()
        observed_bytes = action()
        elapsed = time.perf_counter() - start
        processed_bytes = observed_bytes if observed_bytes is not None else bytes_per_line * iterations
        sample = {
            "seconds": elapsed,
            "lines_per_sec": iterations / elapsed,
            "mib_per_sec": (processed_bytes / (1024 * 1024)) / elapsed,
            "ns_per_line": (elapsed * 1_000_000_000) / iterations,
        }
        samples.append(sample)
        log(
            "info",
            "sample",
            case=name,
            round=round_idx,
            seconds=round(sample["seconds"], 6),
            lines_per_sec=round(sample["lines_per_sec"], 2),
            mib_per_sec=round(sample["mib_per_sec"], 2),
            ns_per_line=round(sample["ns_per_line"], 1),
        )

    summarize_case(name, samples)


@contextmanager
def load_python_binding(skip_build: bool):
    artifact = TARGET_ROOT / "python" / "release" / f"libscrubbers{dylib_extension()}"
    if not skip_build:
        artifact = build_python(verbose=False)
    if not artifact.exists():
        raise FileNotFoundError(f"python artifact not found: {artifact}")

    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    with tempfile.TemporaryDirectory(prefix="scrubbers-python-bench-") as tmp:
        tmp_path = Path(tmp)
        module_path = tmp_path / f"scrubbers{ext_suffix}"
        shutil.copy2(artifact, module_path)
        sys.path.insert(0, tmp)
        try:
            sys.modules.pop("scrubbers", None)
            yield importlib.import_module("scrubbers")
        finally:
            sys.modules.pop("scrubbers", None)
            sys.path.remove(tmp)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Python logging with inline scrubbers redaction.")
    parser.add_argument("--iterations", type=int, default=100_000, help="Log lines per benchmark round")
    parser.add_argument("--rounds", type=int, default=5, help="Benchmark rounds per case")
    parser.add_argument(
        "--message-bytes",
        type=int,
        default=192,
        help="Approximate message size before the logging newline",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Reuse the existing Python binding artifact instead of rebuilding",
    )
    args = parser.parse_args()

    message = build_message(args.message_bytes)
    redacted = "prefix **************************************** suffix"

    with load_python_binding(skip_build=args.skip_build) as scrubbers:
        sample_redaction = scrubbers.scrub_text(
            "prefix ghp_123456789012345678901234567890123456 suffix"
        )
        if sample_redaction != redacted:
            raise RuntimeError(f"unexpected sample redaction: {sample_redaction}")

        log(
            "info",
            "config",
            iterations=args.iterations,
            rounds=args.rounds,
            message_bytes=len(message.encode("utf-8")),
        )

        bytes_per_line = len((message + "\n").encode("utf-8"))

        benchmark_case(
            name="python_binding/direct_scrub_text",
            iterations=args.iterations,
            rounds=args.rounds,
            bytes_per_line=len(message.encode("utf-8")),
            action=lambda: direct_scrub_text(scrubbers, message, args.iterations),
        )

        plain_sink = CountingStream()
        plain_logger = make_logger("plain", PlainFormatter(), plain_sink)
        benchmark_case(
            name="python_logging/plain",
            iterations=args.iterations,
            rounds=args.rounds,
            bytes_per_line=bytes_per_line,
            action=lambda: emit_lines(plain_logger, plain_sink, message, args.iterations),
        )

        redacting_sink = CountingStream()
        redacting_logger = make_logger("redacted", RedactingFormatter(scrubbers), redacting_sink)
        benchmark_case(
            name="python_logging/inline_scrub_text",
            iterations=args.iterations,
            rounds=args.rounds,
            bytes_per_line=bytes_per_line,
            action=lambda: emit_lines(redacting_logger, redacting_sink, message, args.iterations),
        )


def emit_lines(logger: logging.Logger, sink: CountingStream, message: str, iterations: int) -> int:
    sink.reset()
    for _ in range(iterations):
        logger.info(message)
    return sink.bytes_written


def direct_scrub_text(scrubbers_module: object, message: str, iterations: int) -> int:
    total_bytes = 0
    for _ in range(iterations):
        total_bytes += len(scrubbers_module.scrub_text(message).encode("utf-8"))
    return total_bytes


if __name__ == "__main__":
    main()
