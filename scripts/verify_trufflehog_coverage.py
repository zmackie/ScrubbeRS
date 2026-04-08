#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import tempfile

REPO = "https://github.com/trufflesecurity/trufflehog.git"
SKIP_DIRS = {"falsepositives", "detectorspb", "detectors_test", "endpointcustomizer"}


def run(cmd: list[str], cwd: pathlib.Path | None = None) -> str:
    return subprocess.check_output(cmd, cwd=str(cwd) if cwd else None, text=True).strip()


def fetch_repo(repo: str, repo_dir: pathlib.Path, ref: str | None) -> None:
    if not ref:
        run(["git", "clone", "--depth", "1", repo, str(repo_dir)])
        return

    run(["git", "init", str(repo_dir)])
    run(["git", "-C", str(repo_dir), "remote", "add", "origin", repo])
    run(["git", "-C", str(repo_dir), "fetch", "--depth", "1", "origin", ref])
    run(["git", "-C", str(repo_dir), "checkout", "--detach", "FETCH_HEAD"])


def detector_dirs(repo_dir: pathlib.Path) -> set[str]:
    root = repo_dir / "pkg" / "detectors"
    return {
        p.name
        for p in root.iterdir()
        if p.is_dir() and p.name not in SKIP_DIRS
    }


def detectors_in_generated(generated_file: pathlib.Path) -> set[str]:
    txt = generated_file.read_text(encoding="utf-8")
    block = re.search(
        r"pub static TRUFFLEHOG_DETECTORS: &\[&str\] = &\[(?P<body>[\s\S]*?)\n\];",
        txt,
    )
    if not block:
        raise ValueError(
            f"unable to find TRUFFLEHOG_DETECTORS in {generated_file}"
        )
    return set(re.findall(r'^\s*"([^"]+)",$', block.group("body"), re.MULTILINE))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--ref", default=None, help="Optional branch, tag, or commit to compare instead of repo HEAD")
    parser.add_argument("--generated", default="src/generated_trufflehog.rs")
    args = parser.parse_args()

    generated = pathlib.Path(args.generated)
    found = detectors_in_generated(generated)

    with tempfile.TemporaryDirectory(prefix="trufflehog-") as tmp:
        repo_dir = pathlib.Path(tmp) / "trufflehog"
        fetch_repo(args.repo, repo_dir, args.ref)
        expected = detector_dirs(repo_dir)

    missing = sorted(expected - found)
    if missing:
        print("Missing detector coverage for:")
        for name in missing:
            print(f"- {name}")
        return 1

    print(f"Coverage OK: {len(found)} detectors represented in {generated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
