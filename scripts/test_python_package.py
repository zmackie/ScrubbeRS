#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SMOKE_TEST = ROOT / "bindings/python/smoke_test.py"


def log(level: str, event: str, detail: str) -> None:
    print(json.dumps({"level": level, "event": event, "detail": detail}))


def run(cmd: list[str], *, verbose: bool) -> None:
    if verbose:
        log("debug", "exec", " ".join(cmd))
        subprocess.run(cmd, cwd=ROOT, check=True)
        return

    result = subprocess.run(
        cmd,
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode == 0:
        return
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    raise subprocess.CalledProcessError(result.returncode, cmd)


def latest_artifacts(pattern: str) -> list[Path]:
    return sorted(DIST.glob(pattern), key=lambda path: path.stat().st_mtime_ns, reverse=True)


def build_distributions(kind: str, verbose: bool) -> None:
    if kind == "all":
        cmd = ["uv", "build"]
    else:
        cmd = ["uv", "build", f"--{kind}"]
    log("info", "build", " ".join(cmd))
    run(cmd, verbose=verbose)


def smoke_test(artifact: Path, python: str | None, verbose: bool) -> None:
    cmd = ["uv", "run"]
    if python:
        cmd.extend(["--python", python])
    cmd.extend(
        [
            "--isolated",
            "--no-project",
            "--with",
            str(artifact),
            str(SMOKE_TEST),
        ]
    )
    log("info", "smoke", f"testing {artifact.name}")
    run(cmd, verbose=verbose)


def verify_artifact(kind: str, python: str | None, verbose: bool) -> None:
    pattern = "*.whl" if kind == "wheel" else "*.tar.gz"
    artifacts = latest_artifacts(pattern)
    if not artifacts:
        raise FileNotFoundError(f"no {kind} artifacts found in {DIST}")
    smoke_test(artifacts[0], python, verbose)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and smoke test the Python package distributions.")
    parser.add_argument(
        "--artifact",
        choices=["wheel", "sdist", "all"],
        default="all",
        help="Which distribution kind to build and validate",
    )
    parser.add_argument(
        "--python",
        default=None,
        help="Optional Python version or interpreter path to use for uv run smoke tests",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Reuse the current dist/ contents instead of rebuilding",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Stream subprocess output directly",
    )
    args = parser.parse_args()

    if not args.skip_build:
        build_distributions(args.artifact, args.verbose)

    if args.artifact in ("wheel", "all"):
        verify_artifact("wheel", args.python, args.verbose)
    if args.artifact in ("sdist", "all"):
        verify_artifact("sdist", args.python, args.verbose)

    log("info", "done", f"{args.artifact} distribution checks passed")


if __name__ == "__main__":
    main()
