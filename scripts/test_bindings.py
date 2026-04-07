#!/usr/bin/env python3
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET_ROOT = ROOT / "target" / "bindings"


def log(level: str, event: str, detail: str) -> None:
    print(json.dumps({"level": level, "event": event, "detail": detail}))


def run(cmd: list[str], *, env: dict[str, str] | None = None, verbose: bool = False) -> None:
    if verbose:
        log("debug", "exec", " ".join(cmd))
        subprocess.run(cmd, cwd=ROOT, env=env, check=True)
        return

    result = subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        raise subprocess.CalledProcessError(result.returncode, cmd)


def dylib_extension() -> str:
    system = platform.system()
    if system == "Darwin":
        return ".dylib"
    if system == "Windows":
        return ".dll"
    return ".so"


def build_python(verbose: bool) -> Path:
    target_dir = TARGET_ROOT / "python"
    env = os.environ.copy()
    env["PYO3_PYTHON"] = sys.executable
    run(
        [
            "cargo",
            "build",
            "--release",
            "--manifest-path",
            str(ROOT / "bindings/python/Cargo.toml"),
            "--target-dir",
            str(target_dir),
        ],
        env=env,
        verbose=verbose,
    )
    return target_dir / "release" / f"libscrubbers{dylib_extension()}"


def build_node(verbose: bool) -> Path:
    target_dir = TARGET_ROOT / "node"
    run(
        [
            "cargo",
            "build",
            "--release",
            "--manifest-path",
            str(ROOT / "bindings/node/Cargo.toml"),
            "--target-dir",
            str(target_dir),
        ],
        verbose=verbose,
    )
    return target_dir / "release" / f"libscrubbers{dylib_extension()}"


def test_python(skip_build: bool, verbose: bool) -> None:
    log("info", "python", "building python binding")
    artifact = TARGET_ROOT / "python" / "release" / f"libscrubbers{dylib_extension()}"
    if not skip_build:
        artifact = build_python(verbose)
    if not artifact.exists():
        raise FileNotFoundError(f"python artifact not found: {artifact}")

    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    with tempfile.TemporaryDirectory(prefix="scrubbers-python-binding-") as tmp:
        module_path = Path(tmp) / f"scrubbers{ext_suffix}"
        shutil.copy2(artifact, module_path)
        env = os.environ.copy()
        env["PYTHONPATH"] = (
            f"{tmp}{os.pathsep}{env['PYTHONPATH']}" if "PYTHONPATH" in env else tmp
        )
        run([sys.executable, str(ROOT / "bindings/python/smoke_test.py")], env=env, verbose=verbose)
    log("info", "python", "python binding smoke test passed")


def test_node(skip_build: bool, verbose: bool) -> None:
    log("info", "node", "building node binding")
    artifact = TARGET_ROOT / "node" / "release" / f"libscrubbers{dylib_extension()}"
    if not skip_build:
        artifact = build_node(verbose)
    if not artifact.exists():
        raise FileNotFoundError(f"node artifact not found: {artifact}")

    with tempfile.TemporaryDirectory(prefix="scrubbers-node-binding-") as tmp:
        module_path = Path(tmp) / "scrubbers.node"
        shutil.copy2(artifact, module_path)
        run(
            ["node", str(ROOT / "bindings/node/smoke_test.cjs"), str(module_path)],
            verbose=verbose,
        )
    log("info", "node", "node binding smoke test passed")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and smoke test the Python/Node bindings.")
    parser.add_argument(
        "--binding",
        choices=["python", "node", "all"],
        default="all",
        help="Which binding to test",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Reuse existing binding artifacts instead of rebuilding",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Stream subprocess output directly",
    )
    args = parser.parse_args()

    if args.binding in ("python", "all"):
        test_python(args.skip_build, args.verbose)
    if args.binding in ("node", "all"):
        test_node(args.skip_build, args.verbose)

    log("info", "done", f"{args.binding} binding checks passed")


if __name__ == "__main__":
    main()
