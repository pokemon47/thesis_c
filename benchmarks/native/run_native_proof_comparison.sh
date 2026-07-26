#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "${NATIVE_ENV_FILE:-$ROOT/benchmarks/native/benchmark_env.local.sh}"
: "${NATIVE_ADDRESS:?Set NATIVE_ADDRESS to a matched account address}"
RUN_ID="${1:-native_$(date -u +%Y%m%dT%H%M%SZ)}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
for variant in keccak256 poseidon2; do
  url="$NATIVE_KECCAK_RPC_URL"
  [ "$variant" = poseidon2 ] && url="$NATIVE_POSEIDON2_RPC_URL"
  database_id="$NATIVE_KECCAK_DATABASE_ID"
  [ "$variant" = poseidon2 ] && database_id="$NATIVE_POSEIDON2_DATABASE_ID"
  "$PYTHON_BIN" -m thesis_c.benchmark.native_proof --variant "$variant" --rpc-url "$url" \
    --database-id "$database_id" --block "$NATIVE_BLOCK" --address "$NATIVE_ADDRESS" --warmups "$NATIVE_WARMUPS" \
    --repeats "$NATIVE_REPEATS" --output-dir "$ROOT/benchmarks/native_runs/${RUN_ID}_${variant}"
done
