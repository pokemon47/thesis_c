# Portable UltraHONK Benchmark Bundle

This directory contains the portable entrypoints for running the frozen UltraHONK benchmark on another macOS laptop.

## What To Copy

Safe to clone or copy:
- the Thesis repository
- `benchmarks/portable/`
- the frozen datasets and fixture directories
- the frozen benchmark reports
- the optional CRS cache after checksum validation
- the local Besu Poseidon2 helper if the machine architecture matches

Prefer reinstalling or rebuilding:
- the Python virtual environment
- `nargo`, unless you deliberately copied an architecture-compatible binary
- `bb`, unless you deliberately copied an architecture-compatible binary
- Java

Do not copy a Python virtual environment between incompatible paths or architectures.

## Environment Setup

1. Copy the example environment file to a local ignored file:

```bash
cp benchmarks/portable/benchmark_env.example.sh benchmarks/portable/benchmark_env.local.sh
$EDITOR benchmarks/portable/benchmark_env.local.sh
```

2. Set `THESIS_ROOT` to the portable Thesis root on the target laptop.

3. Confirm or override these paths:
- `REPO_ROOT`
- `PYTHON_BIN`
- `NARGO_BIN`
- `BB_BIN`
- `POSEIDON2_CMD`
- `HOME`
- `NARGO_HOME`
- `XDG_CACHE_HOME`
- `CARGO_HOME`
- `CRS_PATH`
- `RUN_ID`

The local environment file is ignored by git via `benchmarks/portable/.gitignore`.

## Toolchain Rules

The bundle validates:
- Python from the Thesis venv
- Nargo `1.0.0-beta.22`
- Barretenberg `5.0.0-nightly.20260522`
- UltraHONK support in BB
- the pinned Poseidon2 helper
- the pinned Poseidon2 dependency revision
- the repository revision
- the writable cache locations
- the CRS cache
- the 14 benchmark fixtures

If a required tool or fixture is missing, the scripts stop with a clear error.

## Preflight

Run the preflight before any benchmark pass:

```bash
benchmarks/portable/preflight_ultrahonk.sh
```

Preflight checks:
- repository revision
- dirty worktree metadata
- Python and package availability
- Nargo and BB versions
- UltraHONK support
- Poseidon2 helper availability
- cache writeability
- CRS files and sizes
- fixture inventory
- focused tests
- disk space
- machine metadata

## CRS Bootstrap

If the CRS cache is missing or incomplete, bootstrap it explicitly:

```bash
benchmarks/portable/bootstrap_crs.sh --bootstrap-crs
```

This script:
- uses the validated local BB CRS bootstrap source
- writes only under `CRS_PATH`
- skips already complete files
- verifies file sizes
- records checksums in `CRS_PATH/crs_manifest.json`

Set `ALLOW_CRS_BOOTSTRAP=1` in `benchmark_env.local.sh` to permit the download.

## Smoke Test

The recommended four-row smoke test is:
- supplied-root Keccak account inclusion
- supplied-root Poseidon2 account inclusion
- anchored Keccak account inclusion
- anchored Poseidon2 balance

Run it with:

```bash
benchmarks/portable/run_four_row_smoke_test.sh
```

The smoke test writes to its own run directory and does not overwrite the full run output.

## Full Pass

Run the frozen 14-row UltraHONK pass with:

```bash
benchmarks/portable/run_full_ultrahonk_pass.sh
```

The full pass covers:
- account inclusion: 4 rows
- balance: 4 rows
- codehash: 4 rows
- eoa activity: 2 rows

Anchored EOA is excluded.

The script writes a fresh run directory under `benchmarks/runs/<RUN_ID>/` and preserves failed rows.

## Resume Failed Rows

Resume failed rows from an existing run directory with:

```bash
benchmarks/portable/resume_failed_ultrahonk_rows.sh benchmarks/runs/<RUN_ID>
```

The resume flow:
- reads the structured `benchmark.json`
- reruns only rows with `status != ok` or `verification_ok != true`
- writes a labeled resume attempt under the original run directory
- leaves successful artifacts untouched
- records a merged summary that separates original failures from resumed attempts

## Output Locations

The full run writes:
- `benchmark.csv`
- `benchmark.json`
- `summary.json`
- `manifest.json`
- `environment.json`
- `report.md`

Row artifacts live under the run directory in `rows/` and `artifacts/`.

## Transferring Results Back

After the run completes on the second laptop, copy the run directory back to the primary machine and compare checksums for:
- the manifest
- the CSV
- the JSON
- the report
- the CRS manifest, if CRS changed

If the run directory is copied to a different filesystem or host, do not assume the same hardware when comparing timings.

## Validation After Transfer

Re-run checksum validation on the copied artifacts and confirm the repository revision in `manifest.json` matches the frozen revision recorded in `benchmark_env.local.sh`.
