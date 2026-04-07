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


def detector_dirs(repo_dir: pathlib.Path) -> set[str]:
    root = repo_dir / "pkg" / "detectors"
    return {
        p.name
        for p in root.iterdir()
        if p.is_dir() and p.name not in SKIP_DIRS
    }


def detectors_in_generated(generated_file: pathlib.Path) -> set[str]:
    txt = generated_file.read_text(encoding="utf-8")
    # Names are encoded as trufflehog_<detector>_<index>
    matches = re.findall(r'trufflehog_([a-zA-Z0-9_]+?)_\d+"', txt)
    return set(matches)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--generated", default="src/generated_trufflehog.rs")
    args = parser.parse_args()

    generated = pathlib.Path(args.generated)
    found = detectors_in_generated(generated)

    with tempfile.TemporaryDirectory(prefix="trufflehog-") as tmp:
        repo_dir = pathlib.Path(tmp) / "trufflehog"
        run(["git", "clone", "--depth", "1", args.repo, str(repo_dir)])
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
