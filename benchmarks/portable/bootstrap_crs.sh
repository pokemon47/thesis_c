#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_ENV_FILE="${BENCHMARK_ENV_FILE:-$SCRIPT_DIR/benchmark_env.local.sh}"

bootstrap_requested=0
if [[ "${1:-}" == "--bootstrap-crs" ]]; then
  bootstrap_requested=1
  shift
fi

if [[ "$bootstrap_requested" -ne 1 ]]; then
  echo "Usage: $0 --bootstrap-crs" >&2
  echo "Set ALLOW_CRS_BOOTSTRAP=1 in benchmark_env.local.sh if you want this to download CRS files." >&2
  exit 2
fi

if [[ ! -f "$LOCAL_ENV_FILE" ]]; then
  echo "Missing local environment file: $LOCAL_ENV_FILE" >&2
  exit 2
fi

# shellcheck source=/dev/null
source "$LOCAL_ENV_FILE"

: "${THESIS_ROOT:?}"
: "${PYTHON_BIN:?}"
: "${CRS_PATH:?}"

if [[ "${ALLOW_CRS_BOOTSTRAP:-0}" != "1" ]]; then
  echo "Refusing to bootstrap CRS because ALLOW_CRS_BOOTSTRAP is not set to 1." >&2
  exit 2
fi

download_script="$THESIS_ROOT/SNARK/aztec-packages-bb/barretenberg/scripts/download_bb_crs.sh"
if [[ ! -x "$download_script" ]]; then
  echo "Missing CRS bootstrap source: $download_script" >&2
  exit 2
fi

mkdir -p "$CRS_PATH"
HOME="$THESIS_ROOT" CRS_PATH="$CRS_PATH" "$download_script"

"$PYTHON_BIN" - "$CRS_PATH" <<'PY'
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
import sys

crs_root = Path(sys.argv[1])
required = ["bn254_g1_compressed.dat", "bn254_g2.dat", "grumpkin_g1.flat.dat"]
records = []
for name in required:
    path = crs_root / name
    if not path.exists() or path.stat().st_size <= 0:
        raise SystemExit(f"Missing or empty CRS file: {path}")
    records.append(
        {
            "path": str(path),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }
    )

manifest = crs_root / "crs_manifest.json"
manifest.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps({"crs_root": str(crs_root), "files": records}, indent=2, sort_keys=True))
PY
