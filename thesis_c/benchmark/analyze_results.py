from __future__ import annotations

import argparse
import itertools
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import pandas as pd

DEFAULT_METRICS: tuple[str, ...] = (
    "proof_generation_time_s",
    "proof_verification_time_s",
    "witness_generation_time_s",
    "compile_time_s",
    "proof_size_bytes",
    "prove_peak_memory_bytes",
    "verify_peak_memory_bytes",
    "circuit_size_bytes",
    "constraint_count",
)
DEFAULT_INCLUDE_STATUSES: tuple[str, ...] = ("ok",)
GROUP_COLUMNS: tuple[str, ...] = ("statement", "hash_name", "backend")

_TRUE_VALUES = {"1", "true", "yes", "y", "t"}
_FALSE_VALUES = {"0", "false", "no", "n", "f"}


@dataclass(slots=True)
class AnalysisOutputs:
    report_dir: Path
    aggregated_csv: Path
    status_summary_csv: Path
    summary_statistics_csv: Path
    backend_comparisons_csv: Path
    hash_comparisons_csv: Path
    plot_paths: list[Path]


def _split_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _safe_slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_") or "metric"


def _as_float(value: object) -> float | None:
    if value is None or pd.isna(value):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_ratio(numerator: object, denominator: object) -> float | None:
    numerator_f = _as_float(numerator)
    denominator_f = _as_float(denominator)
    if numerator_f is None or denominator_f is None or denominator_f == 0.0:
        return None
    return numerator_f / denominator_f


def _discover_benchmark_files(inputs: Sequence[str | Path]) -> list[Path]:
    if not inputs:
        raise ValueError("At least one input path is required.")

    discovered: set[Path] = set()
    for raw_path in inputs:
        path = Path(raw_path).expanduser()
        if not path.exists():
            raise ValueError(f"Input path does not exist: {path}")

        if path.is_file():
            if path.name not in {"benchmark.json", "benchmark.csv"}:
                raise ValueError(
                    f"Unsupported input file '{path}'. Expected benchmark.json or benchmark.csv."
                )
            discovered.add(path.resolve())
            continue

        direct_json = path / "benchmark.json"
        direct_csv = path / "benchmark.csv"
        if direct_json.exists():
            discovered.add(direct_json.resolve())
        elif direct_csv.exists():
            discovered.add(direct_csv.resolve())

        for json_path in path.rglob("benchmark.json"):
            discovered.add(json_path.resolve())
        for csv_path in path.rglob("benchmark.csv"):
            if not (csv_path.parent / "benchmark.json").exists():
                discovered.add(csv_path.resolve())

    files = sorted(discovered)
    if not files:
        raise ValueError("No benchmark.json or benchmark.csv files were found in the input paths.")
    return files


def _read_json_rows(path: Path) -> list[dict[str, object]]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        raise ValueError(f"Expected a list in JSON benchmark file: {path}")

    rows: list[dict[str, object]] = []
    for idx, item in enumerate(loaded):
        if not isinstance(item, dict):
            raise ValueError(f"Row {idx} in {path} is not a JSON object.")
        rows.append(dict(item))
    return rows


def _read_csv_rows(path: Path) -> list[dict[str, object]]:
    frame = pd.read_csv(path)
    return frame.to_dict(orient="records")


def _load_rows(files: Sequence[Path]) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for file_path in files:
        if file_path.suffix == ".json":
            file_rows = _read_json_rows(file_path)
        elif file_path.suffix == ".csv":
            file_rows = _read_csv_rows(file_path)
        else:
            continue

        for row in file_rows:
            payload = dict(row)
            payload["source_file"] = str(file_path)
            payload["source_run"] = file_path.parent.name
            rows.append(payload)

    frame = pd.DataFrame(rows)
    if frame.empty:
        raise ValueError("No benchmark rows were loaded from the provided input files.")
    return frame


def _coerce_bool_series(series: pd.Series) -> pd.Series:
    lowered = series.astype(str).str.strip().str.lower()
    normalized = lowered.map(
        lambda value: True
        if value in _TRUE_VALUES
        else False
        if value in _FALSE_VALUES
        else pd.NA
    )
    return normalized.astype("boolean")


def _normalize_dataframe(frame: pd.DataFrame) -> pd.DataFrame:
    normalized = frame.copy()
    for column in ("dataset_id", "statement", "hash_name", "backend", "error"):
        if column not in normalized:
            normalized[column] = ""

    if "status" not in normalized:
        normalized["status"] = "ok"
    normalized["status"] = (
        normalized["status"]
        .fillna("ok")
        .astype(str)
        .str.strip()
        .replace("", "ok")
    )

    if "verification_ok" in normalized:
        normalized["verification_ok"] = _coerce_bool_series(normalized["verification_ok"])

    numeric_columns = (
        "block_number",
        "proof_generation_time_s",
        "proof_verification_time_s",
        "witness_generation_time_s",
        "compile_time_s",
        "proof_size_bytes",
        "prove_peak_memory_bytes",
        "verify_peak_memory_bytes",
        "circuit_size_bytes",
        "constraint_count",
        "account_proof_node_count",
        "storage_proof_node_count",
        "raw_proof_byte_size",
    )
    for column in numeric_columns:
        if column in normalized:
            normalized[column] = pd.to_numeric(normalized[column], errors="coerce")

    return normalized


def _resolve_metrics(frame: pd.DataFrame, metrics: Sequence[str] | None) -> list[str]:
    if metrics:
        selected = []
        missing: list[str] = []
        for metric in metrics:
            if metric in frame.columns:
                selected.append(metric)
            else:
                missing.append(metric)
        if missing:
            raise ValueError(f"Requested metrics are not present in loaded data: {missing}")
        return selected

    return [metric for metric in DEFAULT_METRICS if metric in frame.columns]


def _resolve_statuses(frame: pd.DataFrame, statuses: Sequence[str] | None) -> list[str]:
    if statuses:
        if len(statuses) == 1 and statuses[0].lower() == "all":
            unique_statuses = sorted(
                {
                    str(status).strip()
                    for status in frame["status"].dropna().tolist()
                    if str(status).strip()
                }
            )
            return unique_statuses
        return sorted({status.strip() for status in statuses if status.strip()})

    return list(DEFAULT_INCLUDE_STATUSES)


def build_status_summary(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame(columns=[*GROUP_COLUMNS, "status", "row_count"])

    grouped = (
        frame.groupby([*GROUP_COLUMNS, "status"], dropna=False)
        .size()
        .rename("row_count")
        .reset_index()
    )
    return grouped.sort_values([*GROUP_COLUMNS, "status"]).reset_index(drop=True)


def build_summary_statistics(
    frame: pd.DataFrame,
    metrics: Sequence[str],
    include_statuses: Sequence[str],
) -> pd.DataFrame:
    columns = [
        *GROUP_COLUMNS,
        "metric",
        "status_filter",
        "count",
        "mean",
        "std",
        "min",
        "q1",
        "median",
        "q3",
        "iqr",
        "max",
    ]
    if frame.empty or not metrics:
        return pd.DataFrame(columns=columns)

    filtered = frame[frame["status"].isin(include_statuses)].copy()
    if filtered.empty:
        return pd.DataFrame(columns=columns)

    output_frames: list[pd.DataFrame] = []
    status_filter = ",".join(include_statuses)
    for metric in metrics:
        if metric not in filtered.columns:
            continue
        metric_frame = filtered[[*GROUP_COLUMNS, metric]].dropna(subset=[metric])
        if metric_frame.empty:
            continue

        grouped = metric_frame.groupby(list(GROUP_COLUMNS), dropna=False)[metric]
        stats = grouped.agg(count="count", mean="mean", std="std", min="min", median="median", max="max")
        q1 = grouped.quantile(0.25).rename("q1")
        q3 = grouped.quantile(0.75).rename("q3")
        merged = stats.join(q1).join(q3).reset_index()
        merged["iqr"] = merged["q3"] - merged["q1"]
        merged["metric"] = metric
        merged["status_filter"] = status_filter
        output_frames.append(merged[columns])

    if not output_frames:
        return pd.DataFrame(columns=columns)

    return (
        pd.concat(output_frames, ignore_index=True)
        .sort_values([*GROUP_COLUMNS, "metric"])
        .reset_index(drop=True)
    )


def build_backend_comparisons(summary_statistics: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "statement",
        "hash_name",
        "metric",
        "baseline_backend",
        "comparison_backend",
        "baseline_median",
        "comparison_median",
        "delta_comparison_minus_baseline",
        "ratio_comparison_over_baseline",
    ]
    if summary_statistics.empty:
        return pd.DataFrame(columns=columns)

    rows: list[dict[str, object]] = []
    grouped = summary_statistics.groupby(["statement", "hash_name", "metric"], dropna=False)
    for (statement, hash_name, metric), group in grouped:
        medians = {
            str(row.backend): row.median
            for row in group.itertuples()
            if pd.notna(row.backend) and pd.notna(row.median)
        }
        if len(medians) < 2:
            continue

        pairings: list[tuple[str, str]] = []
        if "ultra_plonk" in medians and "ultra_honk" in medians:
            pairings.append(("ultra_plonk", "ultra_honk"))
        else:
            pairings.extend(itertools.combinations(sorted(medians.keys()), 2))

        for baseline_backend, comparison_backend in pairings:
            baseline_median = medians.get(baseline_backend)
            comparison_median = medians.get(comparison_backend)
            if baseline_median is None or comparison_median is None:
                continue
            delta = comparison_median - baseline_median
            rows.append(
                {
                    "statement": statement,
                    "hash_name": hash_name,
                    "metric": metric,
                    "baseline_backend": baseline_backend,
                    "comparison_backend": comparison_backend,
                    "baseline_median": baseline_median,
                    "comparison_median": comparison_median,
                    "delta_comparison_minus_baseline": delta,
                    "ratio_comparison_over_baseline": _safe_ratio(
                        comparison_median, baseline_median
                    ),
                }
            )

    if not rows:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame(rows)[columns].sort_values(columns[:5]).reset_index(drop=True)


def build_hash_comparisons(summary_statistics: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "statement",
        "backend",
        "metric",
        "baseline_hash",
        "comparison_hash",
        "baseline_median",
        "comparison_median",
        "delta_comparison_minus_baseline",
        "ratio_comparison_over_baseline",
    ]
    if summary_statistics.empty:
        return pd.DataFrame(columns=columns)

    rows: list[dict[str, object]] = []
    grouped = summary_statistics.groupby(["statement", "backend", "metric"], dropna=False)
    for (statement, backend, metric), group in grouped:
        medians = {
            str(row.hash_name): row.median
            for row in group.itertuples()
            if pd.notna(row.hash_name) and pd.notna(row.median)
        }
        if len(medians) < 2:
            continue

        pairings: list[tuple[str, str]] = []
        if "keccak256" in medians and "poseidon2" in medians:
            pairings.append(("keccak256", "poseidon2"))
        else:
            pairings.extend(itertools.combinations(sorted(medians.keys()), 2))

        for baseline_hash, comparison_hash in pairings:
            baseline_median = medians.get(baseline_hash)
            comparison_median = medians.get(comparison_hash)
            if baseline_median is None or comparison_median is None:
                continue
            delta = comparison_median - baseline_median
            rows.append(
                {
                    "statement": statement,
                    "backend": backend,
                    "metric": metric,
                    "baseline_hash": baseline_hash,
                    "comparison_hash": comparison_hash,
                    "baseline_median": baseline_median,
                    "comparison_median": comparison_median,
                    "delta_comparison_minus_baseline": delta,
                    "ratio_comparison_over_baseline": _safe_ratio(
                        comparison_median, baseline_median
                    ),
                }
            )

    if not rows:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame(rows)[columns].sort_values(columns[:5]).reset_index(drop=True)


def generate_metric_plots(summary_statistics: pd.DataFrame, report_dir: Path) -> list[Path]:
    if summary_statistics.empty:
        return []

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plots_dir = report_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    written_paths: list[Path] = []
    for metric in sorted(summary_statistics["metric"].unique()):
        metric_frame = summary_statistics[summary_statistics["metric"] == metric].copy()
        if metric_frame.empty:
            continue

        metric_frame = metric_frame.sort_values(list(GROUP_COLUMNS)).reset_index(drop=True)
        metric_frame["label"] = (
            metric_frame["statement"].astype(str)
            + " | "
            + metric_frame["hash_name"].astype(str)
            + " | "
            + metric_frame["backend"].astype(str)
        )

        medians = metric_frame["median"].fillna(0.0).astype(float).tolist()
        lower_errors = (
            (metric_frame["median"] - metric_frame["q1"]).clip(lower=0.0).fillna(0.0).astype(float).tolist()
        )
        upper_errors = (
            (metric_frame["q3"] - metric_frame["median"]).clip(lower=0.0).fillna(0.0).astype(float).tolist()
        )

        figure_width = max(10.0, len(metric_frame) * 0.9)
        figure, axis = plt.subplots(figsize=(figure_width, 5.0))
        axis.bar(
            range(len(metric_frame)),
            medians,
            yerr=[lower_errors, upper_errors],
            capsize=4,
        )
        axis.set_title(f"{metric} median with IQR")
        axis.set_ylabel(metric)
        axis.set_xticks(range(len(metric_frame)))
        axis.set_xticklabels(metric_frame["label"].tolist(), rotation=45, ha="right")
        axis.grid(axis="y", linestyle="--", alpha=0.4)
        figure.tight_layout()

        plot_path = plots_dir / f"{_safe_slug(metric)}.png"
        figure.savefig(plot_path, dpi=160)
        plt.close(figure)
        written_paths.append(plot_path)

    return written_paths


def _write_csv(path: Path, frame: pd.DataFrame) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False)


def _prepare_report_dir(output_dir: str | Path | None) -> Path:
    if output_dir:
        report_dir = Path(output_dir)
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_dir = Path("benchmarks/reports") / timestamp
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def analyze_results(
    *,
    inputs: Sequence[str | Path],
    output_dir: str | Path | None = None,
    include_statuses: Sequence[str] | None = None,
    metrics: Sequence[str] | None = None,
    no_plots: bool = False,
) -> AnalysisOutputs:
    files = _discover_benchmark_files(inputs)
    loaded = _load_rows(files)
    normalized = _normalize_dataframe(loaded)

    selected_statuses = _resolve_statuses(normalized, include_statuses)
    selected_metrics = _resolve_metrics(normalized, metrics)
    report_dir = _prepare_report_dir(output_dir)

    aggregated = normalized.sort_values(["source_run", *GROUP_COLUMNS, "dataset_id"]).reset_index(drop=True)
    status_summary = build_status_summary(normalized)
    summary_statistics = build_summary_statistics(normalized, selected_metrics, selected_statuses)
    backend_comparisons = build_backend_comparisons(summary_statistics)
    hash_comparisons = build_hash_comparisons(summary_statistics)

    aggregated_csv = report_dir / "aggregated_rows.csv"
    status_summary_csv = report_dir / "status_summary.csv"
    summary_statistics_csv = report_dir / "summary_statistics.csv"
    backend_comparisons_csv = report_dir / "backend_comparisons.csv"
    hash_comparisons_csv = report_dir / "hash_comparisons.csv"

    _write_csv(aggregated_csv, aggregated)
    _write_csv(status_summary_csv, status_summary)
    _write_csv(summary_statistics_csv, summary_statistics)
    _write_csv(backend_comparisons_csv, backend_comparisons)
    _write_csv(hash_comparisons_csv, hash_comparisons)

    plot_paths: list[Path] = []
    if not no_plots:
        plot_paths = generate_metric_plots(summary_statistics, report_dir)

    return AnalysisOutputs(
        report_dir=report_dir,
        aggregated_csv=aggregated_csv,
        status_summary_csv=status_summary_csv,
        summary_statistics_csv=summary_statistics_csv,
        backend_comparisons_csv=backend_comparisons_csv,
        hash_comparisons_csv=hash_comparisons_csv,
        plot_paths=plot_paths,
    )


def analyze_command(args: argparse.Namespace) -> int:
    inputs = _split_csv(args.input)
    include_statuses = _split_csv(args.include_status)
    metrics = _split_csv(args.metrics) if args.metrics else None

    outputs = analyze_results(
        inputs=inputs,
        output_dir=args.output_dir or None,
        include_statuses=include_statuses or None,
        metrics=metrics,
        no_plots=bool(args.no_plots),
    )

    print(f"Report directory: {outputs.report_dir}")
    print(f"Aggregated CSV: {outputs.aggregated_csv}")
    print(f"Status summary CSV: {outputs.status_summary_csv}")
    print(f"Summary statistics CSV: {outputs.summary_statistics_csv}")
    print(f"Backend comparisons CSV: {outputs.backend_comparisons_csv}")
    print(f"Hash comparisons CSV: {outputs.hash_comparisons_csv}")
    if outputs.plot_paths:
        print(f"Plots generated: {len(outputs.plot_paths)}")
    else:
        print("Plots generated: 0")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m thesis_c.benchmark.analyze_results",
        description="Analyze benchmark CSV/JSON outputs for summary stats and comparisons.",
    )
    parser.add_argument(
        "--input",
        default="benchmarks/raw",
        help=(
            "Comma-separated benchmark input paths. Each path may be a benchmark file, "
            "run directory, or parent directory containing multiple runs."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Optional output report directory. Defaults to benchmarks/reports/<timestamp>.",
    )
    parser.add_argument(
        "--include-status",
        default="ok",
        help="Comma-separated statuses to include in numeric stats, or 'all'.",
    )
    parser.add_argument(
        "--metrics",
        default="",
        help="Optional comma-separated metric columns. Defaults to core benchmark metrics.",
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        help="Skip plot generation.",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    return analyze_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
