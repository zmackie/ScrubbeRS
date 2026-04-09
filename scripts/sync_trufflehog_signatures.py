#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import subprocess
import tempfile
from collections import defaultdict

REPO = "https://github.com/trufflesecurity/trufflehog.git"

# Rust's regex engine can consume TruffleHog's Go `regexp` patterns directly.
# Skip `regexp2` patterns because they rely on .NET-style constructs we can't compile.
RAW_PATTERNS = [
    re.compile(r"regexp\.MustCompile\(`(?P<pat>[^`]+)`\)"),
    re.compile(r'regexp\.MustCompile\("(?P<pat>(?:\\.|[^"\\])+)"\)'),
]

KEYWORD_BLOCK = re.compile(
    r"func\s*\(\s*\w+\s+Scanner\s*\)\s*Keywords\(\)\s*\[\]string\s*\{(?P<body>[\s\S]*?)\n\}",
    re.MULTILINE,
)
QUOTED_STRING = re.compile(r'"((?:\\.|[^"\\])+)"')

SKIP_DIRS = {"falsepositives", "detectorspb", "detectors_test", "endpointcustomizer"}
NAME_HASH_HEX_LEN = 16


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


def escape_rust_raw(pattern: str) -> str:
    if '"#' not in pattern:
        return f'r#"{pattern}"#'
    return '"' + pattern.replace('\\', '\\\\').replace('"', '\\"') + '"'


def detector_slug(detector: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_]+", "_", detector).strip("_").lower()
    return slug or "detector"


def stable_signature_name(detector: str, pattern: str, used: set[str]) -> str:
    slug = detector_slug(detector)
    for salt in range(256):
        payload = f"{detector}\0{pattern}" if salt == 0 else f"{detector}\0{salt}\0{pattern}"
        digest = hashlib.blake2s(payload.encode("utf-8"), digest_size=NAME_HASH_HEX_LEN // 2)
        name = f"trufflehog_{slug}_{digest.hexdigest()}"
        if name not in used:
            used.add(name)
            return name
    raise RuntimeError(f"unable to build stable name for detector {detector!r}")


def extract_patterns(file_path: pathlib.Path) -> list[str]:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    found: list[str] = []
    for rx in RAW_PATTERNS:
        for m in rx.finditer(text):
            pat = m.group("pat").strip()
            if pat and len(pat) >= 4:
                found.append(pat)
    uniq: list[str] = []
    seen = set()
    for pat in found:
        if pat not in seen:
            seen.add(pat)
            uniq.append(pat)
    return uniq


def extract_keywords(file_path: pathlib.Path) -> list[str]:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    out: list[str] = []
    for block in KEYWORD_BLOCK.finditer(text):
        body = block.group("body")
        for m in QUOTED_STRING.finditer(body):
            keyword = bytes(m.group(1), "utf-8").decode("unicode_escape").strip()
            if len(keyword) >= 4:
                out.append(re.escape(keyword))
    uniq: list[str] = []
    seen = set()
    for kw in out:
        if kw not in seen:
            seen.add(kw)
            uniq.append(kw)
    return uniq


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--ref", default=None, help="Optional branch, tag, or commit to fetch instead of repo HEAD")
    parser.add_argument("--out", default="src/generated_trufflehog.rs")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="trufflehog-") as tmp:
        repo_dir = pathlib.Path(tmp) / "trufflehog"
        fetch_repo(args.repo, repo_dir, args.ref)
        commit = run(["git", "rev-parse", "HEAD"], cwd=repo_dir)

        detectors_root = repo_dir / "pkg" / "detectors"
        per_detector: dict[str, list[str]] = defaultdict(list)

        for detector_dir in sorted(detectors_root.iterdir()):
            if not detector_dir.is_dir() or detector_dir.name in SKIP_DIRS:
                continue
            detector = detector_dir.name
            for go_file in sorted(detector_dir.glob("*.go")):
                if go_file.name.endswith("_test.go"):
                    continue
                per_detector[detector].extend(extract_patterns(go_file))
                per_detector[detector].extend(extract_keywords(go_file))

            seen = set()
            uniq = []
            for p in per_detector[detector]:
                if p not in seen:
                    seen.add(p)
                    uniq.append(p)
            per_detector[detector] = sorted(uniq)

            if not per_detector[detector]:
                # Ensure detector-family coverage remains explicit in CI diffs
                # even when upstream detectors rely on non-regex verification.
                per_detector[detector] = [re.escape(detector)]

        lines = [
            "// @generated by scripts/sync_trufflehog_signatures.py",
            f"// source: {args.repo} @ {commit}",
            "// signature names are content-addressed so tuple order is not part of identity",
            "",
            f'pub const TRUFFLEHOG_SOURCE_COMMIT: &str = "{commit}";',
            "",
            "pub static TRUFFLEHOG_DETECTORS: &[&str] = &[",
        ]

        for detector in sorted(per_detector):
            lines.append(f'    "{detector}",')

        lines.extend([
            "];",
            "",
            "pub static TRUFFLEHOG_SIGNATURES: &[(&str, &str, &str)] = &[",
        ])

        total = 0
        used_names: set[str] = set()
        for detector, patterns in sorted(per_detector.items()):
            if not patterns:
                continue
            for pat in patterns:
                name = stable_signature_name(detector, pat, used_names)
                lines.append(
                    f'    ("{detector}", "{name}", {escape_rust_raw(pat)}),'
                )
                total += 1

        lines.append("];\n")
        pathlib.Path(args.out).write_text("\n".join(lines), encoding="utf-8")
        run(["rustfmt", args.out])
        print(f"wrote {args.out} with {total} signatures from {len(per_detector)} detector dirs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
