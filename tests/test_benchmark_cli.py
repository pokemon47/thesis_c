from __future__ import annotations

from thesis_c.cli import build_parser, benchmark_command


def test_benchmark_parser_defaults_to_ultra_honk_only() -> None:
    parser = build_parser()
    args = parser.parse_args(["benchmark", "--input", "input.json"])

    assert args.backends == "ultra_honk"
    assert args.proving_system == "ultra_honk"
    assert args.bb_binary == "/Users/doodleaks/.bb/bb"


def test_benchmark_command_rejects_ultra_plonk_backend(capsys) -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["benchmark", "--input", "input.json", "--backends", "ultra_plonk"]
    )

    assert benchmark_command(args) == 2
    output = capsys.readouterr().out
    assert "Unsupported backend(s) for benchmark runner" in output


def test_benchmark_command_rejects_non_ultra_honk_proving_system(capsys) -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "benchmark",
            "--input",
            "input.json",
            "--backends",
            "ultra_honk",
            "--proving-system",
            "ultra_plonk",
        ]
    )

    assert benchmark_command(args) == 2
    output = capsys.readouterr().out
    assert "Unsupported proving system for benchmark runner" in output
