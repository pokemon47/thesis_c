#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_ENV_FILE="${BENCHMARK_ENV_FILE:-$SCRIPT_DIR/benchmark_env.local.sh}"

run_dir="${1:-${RUN_DIR:-}}"
resume_id="${2:-${RESUME_ID:-}}"

if [[ -z "$run_dir" ]]; then
  echo "Usage: $0 <existing-run-dir> [resume-id]" >&2
  exit 2
fi

if [[ ! -f "$LOCAL_ENV_FILE" ]]; then
  echo "Missing local environment file: $LOCAL_ENV_FILE" >&2
  exit 2
fi

# shellcheck source=/dev/null
source "$LOCAL_ENV_FILE"

: "${THESIS_ROOT:?}"
: "${REPO_ROOT:?}"
: "${PYTHON_BIN:?}"

cd "$REPO_ROOT"

if [[ -n "$resume_id" ]]; then
  "$PYTHON_BIN" -m thesis_c.benchmark.portable_bundle resume "$run_dir" --resume-id "$resume_id"
else
  "$PYTHON_BIN" -m thesis_c.benchmark.portable_bundle resume "$run_dir"
fi
