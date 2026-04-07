#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${BINARY:-$ROOT_DIR/target/release/scrubbers}"
VERBOSE=0
SKIP_BUILD=0

usage() {
  cat <<'EOF'
Usage: scripts/manual_smoke.sh [--skip-build] [--verbose] [--binary PATH]

Manual smoke checks:
1. Plain text passes through unchanged.
2. A built-in secret is partially redacted.
3. A custom .scrub literal only redacts the matched span.

Options:
  --skip-build    Reuse the current binary instead of running cargo build --release
  --verbose       Print command-level debug output
  --binary PATH   Override the binary path
  --help          Show this message
EOF
}

log_json() {
  local level="$1"
  local event="$2"
  local detail="$3"
  printf '{"level":"%s","event":"%s","detail":"%s"}\n' "$level" "$event" "$detail"
}

debug() {
  if (( VERBOSE )); then
    log_json "debug" "$1" "$2"
  fi
}

while (($# > 0)); do
  case "$1" in
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --verbose)
      VERBOSE=1
      shift
      ;;
    --binary)
      BINARY="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if (( ! SKIP_BUILD )); then
  log_json "info" "build" "running cargo build --release"
  cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml"
fi

if [[ ! -x "$BINARY" ]]; then
  printf 'Binary not found or not executable: %s\n' "$BINARY" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/scrubbers-manual-smoke-XXXXXX")"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

run_case() {
  local name="$1"
  local expected_file="$2"
  local actual_file="$3"

  if cmp -s "$expected_file" "$actual_file"; then
    log_json "info" "pass" "$name"
  else
    log_json "error" "fail" "$name"
    printf 'Expected bytes:\n' >&2
    xxd -g 1 "$expected_file" >&2
    printf 'Actual bytes:\n' >&2
    xxd -g 1 "$actual_file" >&2
    exit 1
  fi
}

debug "binary" "$BINARY"

printf 'test\n' > "$TMP_DIR/plain.expected"
printf 'test\n' | "$BINARY" > "$TMP_DIR/plain.actual"
run_case "plain_text_passthrough" "$TMP_DIR/plain.expected" "$TMP_DIR/plain.actual"

builtin_input=$'prefix ghp_123456789012345678901234567890123456 suffix\n'
printf '%s' "$builtin_input" | "$BINARY" > "$TMP_DIR/builtin.actual"
printf 'prefix **************************************** suffix\n' > "$TMP_DIR/builtin.expected"
run_case "builtin_secret_partial_redaction" "$TMP_DIR/builtin.expected" "$TMP_DIR/builtin.actual"

printf 'secret\n' > "$TMP_DIR/demo.scrub"
printf 'test_secret_test\n' | "$BINARY" --scrub-file "$TMP_DIR/demo.scrub" > "$TMP_DIR/custom.actual"
printf 'test_******_test\n' > "$TMP_DIR/custom.expected"
run_case "custom_scrub_file_partial_redaction" "$TMP_DIR/custom.expected" "$TMP_DIR/custom.actual"

log_json "info" "done" "all manual smoke checks passed"
