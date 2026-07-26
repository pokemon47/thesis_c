#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_ENV_FILE="${BENCHMARK_ENV_FILE:-$SCRIPT_DIR/benchmark_env.local.sh}"

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

"$PYTHON_BIN" -m thesis_c.benchmark.portable_bundle run-full \
  --run-id "${RUN_ID:-}" \
  --repeat "${REPEAT_COUNT:-1}"
