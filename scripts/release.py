#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION_FILES = [
    ROOT / "Cargo.toml",
    ROOT / "bindings/python/Cargo.toml",
    ROOT / "bindings/node/Cargo.toml",
]


def log(level: str, event: str, detail: str, **fields: object) -> None:
    payload: dict[str, object] = {"level": level, "event": event, "detail": detail}
    payload.update(fields)
    print(json.dumps(payload))


def run(
    cmd: list[str],
    *,
    verbose: bool,
    capture_output: bool = False,
    mutate: bool = False,
    dry_run: bool = False,
) -> str:
    log(
        "debug" if verbose else "info",
        "exec",
        " ".join(cmd),
        mutate=mutate,
        dry_run=dry_run and mutate,
    )
    if dry_run and mutate:
        return ""

    stream_output = verbose and mutate and not capture_output
    result = subprocess.run(
        cmd,
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=not stream_output,
    )
    if result.returncode == 0:
        if capture_output and result.stdout:
            return result.stdout.strip()
        return ""

    if not stream_output:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    raise subprocess.CalledProcessError(result.returncode, cmd)


def read_version(path: Path) -> str:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return data["package"]["version"]


def release_version() -> str:
    versions = {path: read_version(path) for path in VERSION_FILES}
    distinct_versions = {version for version in versions.values()}
    if len(distinct_versions) != 1:
        detail = ", ".join(f"{path.relative_to(ROOT)}={version}" for path, version in versions.items())
        raise RuntimeError(f"version mismatch across release manifests: {detail}")
    return distinct_versions.pop()


def ensure_clean_worktree(*, verbose: bool) -> None:
    tracked_changes = run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        verbose=verbose,
        capture_output=True,
    )
    if tracked_changes:
        raise RuntimeError("tracked changes present; commit or stash them before releasing")

    status_output = run(
        ["git", "status", "--porcelain"],
        verbose=verbose,
        capture_output=True,
    )
    untracked = [line[3:] for line in status_output.splitlines() if line.startswith("?? ")]
    if untracked:
        log("warning", "untracked", "untracked paths present; release will continue", paths=untracked)


def current_branch(*, verbose: bool) -> str:
    return run(["git", "branch", "--show-current"], verbose=verbose, capture_output=True)


def ensure_branch(branch: str, *, verbose: bool, dry_run: bool) -> None:
    current = current_branch(verbose=verbose)
    if current == branch:
        log("info", "branch", f"already on {branch}")
        return
    run(["git", "switch", branch], verbose=verbose, mutate=True, dry_run=dry_run)


def ensure_tag_missing(tag: str, *, remote: str, verbose: bool, dry_run: bool) -> None:
    local_tag = run(["git", "tag", "--list", tag], verbose=verbose, capture_output=True)
    if local_tag:
        raise RuntimeError(f"local tag already exists: {tag}")

    if dry_run:
        log("info", "tag-check", f"skipping remote tag check for {tag} in dry-run mode")
        return

    remote_tag = run(
        ["git", "ls-remote", "--tags", remote, f"refs/tags/{tag}"],
        verbose=verbose,
        capture_output=True,
    )
    if remote_tag:
        raise RuntimeError(f"remote tag already exists on {remote}: {tag}")


def verify_release_prereqs(*, verbose: bool) -> None:
    log("info", "verify", "checking release prerequisites")
    run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"],
        verbose=verbose,
        capture_output=True,
    )
    log("info", "verify", "release prerequisites passed")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create and push a release tag from the repo version.")
    parser.add_argument(
        "--branch",
        default="main",
        help="Branch to release from after merge",
    )
    parser.add_argument(
        "--remote",
        default="origin",
        help="Git remote to pull from and push to",
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Override the release version instead of reading the Cargo manifests",
    )
    parser.add_argument(
        "--skip-pull",
        action="store_true",
        help="Skip pulling the release branch before pushing and tagging",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log release actions without mutating git state",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Stream mutating subprocess output directly",
    )
    args = parser.parse_args()

    ensure_clean_worktree(verbose=args.verbose)

    version = args.version or release_version()
    tag = f"v{version}"
    log("info", "release", f"preparing {tag}", branch=args.branch, remote=args.remote)

    ensure_branch(args.branch, verbose=args.verbose, dry_run=args.dry_run)
    if not args.skip_pull:
        run(
            ["git", "pull", "--ff-only", args.remote, args.branch],
            verbose=args.verbose,
            mutate=True,
            dry_run=args.dry_run,
        )

    verify_release_prereqs(verbose=args.verbose)
    ensure_tag_missing(tag, remote=args.remote, verbose=args.verbose, dry_run=args.dry_run)
    run(["git", "push", args.remote, args.branch], verbose=args.verbose, mutate=True, dry_run=args.dry_run)
    run(["git", "tag", tag], verbose=args.verbose, mutate=True, dry_run=args.dry_run)
    run(["git", "push", args.remote, tag], verbose=args.verbose, mutate=True, dry_run=args.dry_run)
    log("info", "done", f"release {tag} prepared and pushed")


if __name__ == "__main__":
    main()
