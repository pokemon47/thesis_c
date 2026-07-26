#!/usr/bin/env bash
# shellcheck shell=bash

# Copy this file to benchmark_env.local.sh and edit the local copy.
# Keep THESIS_ROOT pointed at the portable Thesis root on the target machine.

export THESIS_ROOT="${THESIS_ROOT:-/path/to/Thesis}"
export REPO_ROOT="${REPO_ROOT:-$THESIS_ROOT/SNARK/thesis_c}"

export PYTHON_BIN="${PYTHON_BIN:-$THESIS_ROOT/.venv/bin/python}"

if [[ -z "${NARGO_BIN:-}" ]] && command -v nargo >/dev/null 2>&1; then
  export NARGO_BIN="$(command -v nargo)"
fi

if [[ -z "${BB_BIN:-}" && -x "${HOME:-$THESIS_ROOT}/.bb/bb" ]]; then
  export BB_BIN="${HOME:-$THESIS_ROOT}/.bb/bb"
fi

if [[ -z "${POSEIDON2_CMD:-}" ]]; then
  _poseidon2_default="$THESIS_ROOT/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash"
  if [[ -x "$_poseidon2_default" ]]; then
    export POSEIDON2_CMD="$_poseidon2_default {hex0x}"
  fi
  unset _poseidon2_default
fi

# The benchmark runner consumes the same helper through its hash adapter.
export THESIS_C_POSEIDON2_CMD="${THESIS_C_POSEIDON2_CMD:-${POSEIDON2_CMD:-}}"

export HOME="${HOME:-$THESIS_ROOT}"
export NARGO_HOME="${NARGO_HOME:-$THESIS_ROOT/nargo}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$THESIS_ROOT/.cache}"
export CARGO_HOME="${CARGO_HOME:-$THESIS_ROOT/.cargo}"
export CRS_PATH="${CRS_PATH:-$THESIS_ROOT/.bb-crs}"

export RUN_ID="${RUN_ID:-}"
export REPEAT_COUNT="${REPEAT_COUNT:-1}"
export RESUME_ID="${RESUME_ID:-}"

export EXPECTED_REPO_REVISION="${EXPECTED_REPO_REVISION:-0d8bf3d9554136d599a116c40a525b8a29b84a17}"
export EXPECTED_NARGO_VERSION="${EXPECTED_NARGO_VERSION:-1.0.0-beta.22}"
export EXPECTED_BB_VERSION="${EXPECTED_BB_VERSION:-5.0.0-nightly.20260522}"
export EXPECTED_POSEIDON2_DEPENDENCY_REVISION="${EXPECTED_POSEIDON2_DEPENDENCY_REVISION:-56f8b45745ebebb0b788d26867e7a89b7363ced7}"

# Set to 1 if you explicitly want bootstrap_crs.sh to perform the download.
export ALLOW_CRS_BOOTSTRAP="${ALLOW_CRS_BOOTSTRAP:-0}"
