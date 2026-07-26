# Benchmark Outputs

- `raw/`: run-specific output folders created by `thesis-c benchmark`.
- `reports/`: optional derived summaries/plots.

Each raw benchmark run writes:

- `benchmark.csv`
- `benchmark.json`
- backend artifacts grouped by hash/backend/statement/sample.

Rows include `status`:

- `ok`
- `missing_dataset`
- `proxy`
- `error`
- `unavailable`: requested proving system is not supported by the pinned toolchain.

The primary benchmark plan is UltraHONK-only. Unsupported proving-system labels
must fail explicitly; they are not remapped to UltraHONK.

The frozen benchmark matrix currently has 16 intended rows, 14 eligible real rows,
and 2 blocked anchored EOA rows.

Legacy UltraPLONK compatibility reports remain preserved under `reports/` for
reference, but they are not part of the primary benchmark campaign.
UltraPLONK is excluded because the frozen source cannot be reproduced under the
compatible legacy compiler/backend generation.
