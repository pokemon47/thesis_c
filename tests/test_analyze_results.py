from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import pandas as pd

from thesis_c.benchmark.analyze_results import analyze_results
from thesis_c.cli import build_parser


def _base_row(
    *,
    dataset_id: str,
    hash_name: str,
    backend: str,
    proof_generation_time_s: float,
    status: str = "ok",
    error: str | None = None,
) -> dict[str, object]:
    return {
        "dataset_id": dataset_id,
        "statement": "account_inclusion",
        "hash_name": hash_name,
        "backend": backend,
        "address": "0x6cc9397c3b38739dacbfaa68ead5f5d77ba5f455",
        "block_number": 1,
        "proof_generation_time_s": proof_generation_time_s,
        "proof_verification_time_s": proof_generation_time_s / 10.0,
        "witness_generation_time_s": proof_generation_time_s / 5.0,
        "compile_time_s": proof_generation_time_s / 20.0,
        "proof_size_bytes": 1024,
        "prove_peak_memory_bytes": 2048,
        "verify_peak_memory_bytes": 1024,
        "circuit_size_bytes": 4096,
        "constraint_count": 2048,
        "account_proof_node_count": 4,
        "storage_proof_node_count": 0,
        "raw_proof_byte_size": 1232,
        "verification_ok": status == "ok",
        "status": status,
        "error": error,
    }


def _write_benchmark_json(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, indent=2), encoding="utf-8")


def _read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path)


class AnalyzeResultsTests(unittest.TestCase):
    def _sample_rows(self) -> list[dict[str, object]]:
        return [
            _base_row(
                dataset_id="sample_0",
                hash_name="keccak256",
                backend="ultra_plonk",
                proof_generation_time_s=10.0,
            ),
            _base_row(
                dataset_id="sample_1",
                hash_name="keccak256",
                backend="ultra_plonk",
                proof_generation_time_s=14.0,
            ),
            _base_row(
                dataset_id="sample_2",
                hash_name="keccak256",
                backend="ultra_honk",
                proof_generation_time_s=8.0,
            ),
            _base_row(
                dataset_id="sample_3",
                hash_name="keccak256",
                backend="ultra_honk",
                proof_generation_time_s=12.0,
            ),
            _base_row(
                dataset_id="sample_4",
                hash_name="poseidon2",
                backend="ultra_plonk",
                proof_generation_time_s=6.0,
            ),
            _base_row(
                dataset_id="sample_5",
                hash_name="poseidon2",
                backend="ultra_plonk",
                proof_generation_time_s=10.0,
            ),
            _base_row(
                dataset_id="sample_error",
                hash_name="keccak256",
                backend="ultra_plonk",
                proof_generation_time_s=1000.0,
                status="error",
                error="nargo missing",
            ),
            _base_row(
                dataset_id="sample_proxy",
                hash_name="poseidon2",
                backend="ultra_honk",
                proof_generation_time_s=0.0,
                status="proxy",
                error="proxy_hash_cost_poseidon2_not_in_circuit",
            ),
        ]

    def test_analysis_outputs_and_default_status_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir) / "raw" / "run_a"
            output_dir = Path(tmp_dir) / "reports" / "run_a"
            rows = self._sample_rows()
            _write_benchmark_json(run_dir / "benchmark.json", rows)

            outputs = analyze_results(
                inputs=[run_dir],
                output_dir=output_dir,
                metrics=["proof_generation_time_s"],
                no_plots=True,
            )

            self.assertTrue(outputs.aggregated_csv.exists())
            self.assertTrue(outputs.status_summary_csv.exists())
            self.assertTrue(outputs.summary_statistics_csv.exists())
            self.assertTrue(outputs.backend_comparisons_csv.exists())
            self.assertTrue(outputs.hash_comparisons_csv.exists())

            aggregated = _read_csv(outputs.aggregated_csv)
            self.assertEqual(len(aggregated), len(rows))

            summary = _read_csv(outputs.summary_statistics_csv)
            plonk_keccak = summary[
                (summary["statement"] == "account_inclusion")
                & (summary["hash_name"] == "keccak256")
                & (summary["backend"] == "ultra_plonk")
                & (summary["metric"] == "proof_generation_time_s")
            ].iloc[0]
            self.assertEqual(int(plonk_keccak["count"]), 2)
            self.assertAlmostEqual(float(plonk_keccak["median"]), 12.0)
            self.assertAlmostEqual(float(plonk_keccak["q1"]), 11.0)
            self.assertAlmostEqual(float(plonk_keccak["q3"]), 13.0)
            self.assertAlmostEqual(float(plonk_keccak["iqr"]), 2.0)
            self.assertEqual(str(plonk_keccak["status_filter"]), "ok")

            backend_comparisons = _read_csv(outputs.backend_comparisons_csv)
            backend_row = backend_comparisons[
                (backend_comparisons["statement"] == "account_inclusion")
                & (backend_comparisons["hash_name"] == "keccak256")
                & (backend_comparisons["metric"] == "proof_generation_time_s")
            ].iloc[0]
            self.assertEqual(str(backend_row["baseline_backend"]), "ultra_plonk")
            self.assertEqual(str(backend_row["comparison_backend"]), "ultra_honk")
            self.assertAlmostEqual(float(backend_row["baseline_median"]), 12.0)
            self.assertAlmostEqual(float(backend_row["comparison_median"]), 10.0)
            self.assertAlmostEqual(
                float(backend_row["delta_comparison_minus_baseline"]), -2.0
            )

            hash_comparisons = _read_csv(outputs.hash_comparisons_csv)
            hash_row = hash_comparisons[
                (hash_comparisons["statement"] == "account_inclusion")
                & (hash_comparisons["backend"] == "ultra_plonk")
                & (hash_comparisons["metric"] == "proof_generation_time_s")
            ].iloc[0]
            self.assertEqual(str(hash_row["baseline_hash"]), "keccak256")
            self.assertEqual(str(hash_row["comparison_hash"]), "poseidon2")
            self.assertAlmostEqual(float(hash_row["baseline_median"]), 12.0)
            self.assertAlmostEqual(float(hash_row["comparison_median"]), 8.0)
            self.assertAlmostEqual(float(hash_row["ratio_comparison_over_baseline"]), 2.0 / 3.0)

            status_summary = _read_csv(outputs.status_summary_csv)
            status_rows = status_summary[
                (status_summary["statement"] == "account_inclusion")
                & (status_summary["hash_name"] == "keccak256")
                & (status_summary["backend"] == "ultra_plonk")
            ]
            counts = {str(row["status"]): int(row["row_count"]) for _, row in status_rows.iterrows()}
            self.assertEqual(counts.get("ok"), 2)
            self.assertEqual(counts.get("error"), 1)

    def test_include_status_all_includes_error_rows_in_numeric_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir) / "raw" / "run_a"
            output_dir = Path(tmp_dir) / "reports" / "all_status"
            _write_benchmark_json(run_dir / "benchmark.json", self._sample_rows())

            outputs = analyze_results(
                inputs=[run_dir],
                output_dir=output_dir,
                include_statuses=["all"],
                metrics=["proof_generation_time_s"],
                no_plots=True,
            )

            summary = _read_csv(outputs.summary_statistics_csv)
            plonk_keccak = summary[
                (summary["statement"] == "account_inclusion")
                & (summary["hash_name"] == "keccak256")
                & (summary["backend"] == "ultra_plonk")
                & (summary["metric"] == "proof_generation_time_s")
            ].iloc[0]
            self.assertEqual(int(plonk_keccak["count"]), 3)
            self.assertAlmostEqual(float(plonk_keccak["median"]), 14.0)
            self.assertIn("error", str(plonk_keccak["status_filter"]))
            self.assertIn("ok", str(plonk_keccak["status_filter"]))

    def test_cli_analyze_subcommand_writes_reports(self) -> None:
        parser = build_parser()
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir) / "raw" / "run_a"
            output_dir = Path(tmp_dir) / "reports" / "from_cli"
            _write_benchmark_json(run_dir / "benchmark.json", self._sample_rows())

            args = parser.parse_args(
                [
                    "analyze",
                    "--input",
                    str(run_dir),
                    "--output-dir",
                    str(output_dir),
                    "--metrics",
                    "proof_generation_time_s",
                    "--no-plots",
                ]
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = args.func(args)

            self.assertEqual(exit_code, 0)
            self.assertTrue((output_dir / "aggregated_rows.csv").exists())
            self.assertTrue((output_dir / "summary_statistics.csv").exists())
            self.assertIn("Report directory:", stdout.getvalue())

    def test_plot_generation_writes_png_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir) / "raw" / "run_a"
            output_dir = Path(tmp_dir) / "reports" / "plots"
            _write_benchmark_json(run_dir / "benchmark.json", self._sample_rows())

            outputs = analyze_results(
                inputs=[run_dir],
                output_dir=output_dir,
                metrics=["proof_generation_time_s"],
                no_plots=False,
            )

            self.assertGreater(len(outputs.plot_paths), 0)
            for plot_path in outputs.plot_paths:
                self.assertTrue(plot_path.exists())
                self.assertEqual(plot_path.suffix, ".png")


if __name__ == "__main__":
    unittest.main()
