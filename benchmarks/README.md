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
