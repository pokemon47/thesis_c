#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_ENV_FILE="${BENCHMARK_ENV_FILE:-$SCRIPT_DIR/benchmark_env.local.sh}"

if [[ ! -f "$LOCAL_ENV_FILE" ]]; then
  echo "Missing local environment file: $LOCAL_ENV_FILE" >&2
  echo "Copy benchmark_env.example.sh to benchmark_env.local.sh and edit it first." >&2
  exit 2
fi

# shellcheck source=/dev/null
source "$LOCAL_ENV_FILE"

: "${THESIS_ROOT:?}"
: "${REPO_ROOT:?}"
: "${PYTHON_BIN:?}"

cd "$REPO_ROOT"

"$PYTHON_BIN" -m thesis_c.benchmark.portable_bundle preflight --matrix full
"$PYTHON_BIN" -m pytest \
  tests/test_portable_ultrahonk_bundle.py \
  tests/test_benchmark_cli.py \
  tests/test_runner_artifact_isolation.py \
  tests/test_task3f_freeze.py \
  -q
