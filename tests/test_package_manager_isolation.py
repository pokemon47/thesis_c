from __future__ import annotations

from pathlib import Path

import pytest

from thesis_c.noir.artifacts import CircuitPackage
from thesis_c.noir.package_manager import CommandResult, compile_isolated, execute_witness_isolated


def test_compile_isolated_clears_stale_circuit_json(tmp_path: Path, monkeypatch) -> None:
    package_dir = tmp_path / "circuits_poseidon2"
    package_dir.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    expected_circuit_json = target_dir / "thesis_c_circuits_poseidon2.json"
    expected_circuit_json.write_text("stale", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    package = CircuitPackage(
        statement="account_inclusion",
        hash_name="poseidon2",
        package_dir=package_dir,
        nargo_package_name="thesis_c_circuits_poseidon2",
        expected_circuit_json=expected_circuit_json,
    )

    def fake_run(command: list[str], cwd: Path) -> CommandResult:
        assert not expected_circuit_json.exists()
        expected_circuit_json.write_text("fresh", encoding="utf-8")
        return CommandResult(command=command, elapsed_s=0.01, stdout="ok", stderr="")

    monkeypatch.setattr("thesis_c.noir.package_manager._run", fake_run)

    result = compile_isolated(package, run_dir=run_dir)

    assert result.stdout == "ok"
    assert expected_circuit_json.read_text(encoding="utf-8") == "fresh"
    assert (run_dir / "circuit.json").read_text(encoding="utf-8") == "fresh"


def test_compile_isolated_leaves_other_package_artifacts_untouched(
    tmp_path: Path, monkeypatch
) -> None:
    package_dir = tmp_path / "circuits_poseidon2"
    package_dir.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    expected_circuit_json = target_dir / "thesis_c_circuits_poseidon2.json"
    other_circuit_json = target_dir / "thesis_c_circuits_poseidon2_extra.json"
    expected_circuit_json.write_text("stale", encoding="utf-8")
    other_circuit_json.write_text("other", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    package = CircuitPackage(
        statement="account_inclusion",
        hash_name="poseidon2",
        package_dir=package_dir,
        nargo_package_name="thesis_c_circuits_poseidon2",
        expected_circuit_json=expected_circuit_json,
    )

    def fake_run(command: list[str], cwd: Path) -> CommandResult:
        assert not expected_circuit_json.exists()
        assert other_circuit_json.exists()
        expected_circuit_json.write_text("fresh", encoding="utf-8")
        return CommandResult(command=command, elapsed_s=0.01, stdout="ok", stderr="")

    monkeypatch.setattr("thesis_c.noir.package_manager._run", fake_run)

    compile_isolated(package, run_dir=run_dir)

    assert other_circuit_json.read_text(encoding="utf-8") == "other"


def test_execute_witness_isolated_clears_stale_witness(tmp_path: Path, monkeypatch) -> None:
    package_dir = tmp_path / "circuits_poseidon2"
    package_dir.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    expected_witness = target_dir / "poseidon2_memory_0__poseidon2__ultra_honk__fixedrun_witness.gz"
    expected_witness.write_text("stale", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    package = CircuitPackage(
        statement="eoa_activity_anchored_poseidon2",
        hash_name="poseidon2",
        package_dir=package_dir,
        nargo_package_name="thesis_c_circuits_eoa_activity_anchored_poseidon2",
        expected_circuit_json=target_dir / "thesis_c_circuits_eoa_activity_anchored_poseidon2.json",
    )

    def fake_run(command: list[str], cwd: Path) -> CommandResult:
        assert not expected_witness.exists()
        expected_witness.write_text("fresh", encoding="utf-8")
        return CommandResult(command=command, elapsed_s=0.02, stdout="ok", stderr="")

    monkeypatch.setattr("thesis_c.noir.package_manager._run", fake_run)

    result = execute_witness_isolated(
        package,
        witness_name="poseidon2_memory_0__poseidon2__ultra_honk__fixedrun_witness",
        run_dir=run_dir,
    )

    assert result.stdout == "ok"
    assert expected_witness.read_text(encoding="utf-8") == "fresh"
    assert (run_dir / "witness.gz").read_text(encoding="utf-8") == "fresh"


def test_execute_witness_isolated_leaves_other_witnesses_untouched(
    tmp_path: Path, monkeypatch
) -> None:
    package_dir = tmp_path / "circuits_poseidon2"
    package_dir.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    expected_witness = target_dir / "poseidon2_memory_0__poseidon2__ultra_honk__fixedrun_witness.gz"
    other_witness = target_dir / "other_witness.gz"
    expected_witness.write_text("stale", encoding="utf-8")
    other_witness.write_text("other", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    package = CircuitPackage(
        statement="eoa_activity_anchored_poseidon2",
        hash_name="poseidon2",
        package_dir=package_dir,
        nargo_package_name="thesis_c_circuits_eoa_activity_anchored_poseidon2",
        expected_circuit_json=target_dir / "thesis_c_circuits_eoa_activity_anchored_poseidon2.json",
    )

    def fake_run(command: list[str], cwd: Path) -> CommandResult:
        assert not expected_witness.exists()
        assert other_witness.exists()
        expected_witness.write_text("fresh", encoding="utf-8")
        return CommandResult(command=command, elapsed_s=0.02, stdout="ok", stderr="")

    monkeypatch.setattr("thesis_c.noir.package_manager._run", fake_run)

    execute_witness_isolated(
        package,
        witness_name="poseidon2_memory_0__poseidon2__ultra_honk__fixedrun_witness",
        run_dir=run_dir,
    )

    assert other_witness.read_text(encoding="utf-8") == "other"


def test_missing_stale_files_do_not_fail(tmp_path: Path, monkeypatch) -> None:
    package_dir = tmp_path / "circuits_poseidon2"
    package_dir.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    expected_circuit_json = target_dir / "thesis_c_circuits_poseidon2.json"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    package = CircuitPackage(
        statement="account_inclusion",
        hash_name="poseidon2",
        package_dir=package_dir,
        nargo_package_name="thesis_c_circuits_poseidon2",
        expected_circuit_json=expected_circuit_json,
    )

    def fake_run_compile(command: list[str], cwd: Path) -> CommandResult:
        expected_circuit_json.write_text("fresh", encoding="utf-8")
        return CommandResult(command=command, elapsed_s=0.01, stdout="ok", stderr="")

    monkeypatch.setattr("thesis_c.noir.package_manager._run", fake_run_compile)
    compile_isolated(package, run_dir=run_dir)

    expected_witness = target_dir / "poseidon2_memory_0__poseidon2__ultra_honk__fixedrun_witness.gz"

    def fake_run_execute(command: list[str], cwd: Path) -> CommandResult:
        expected_witness.write_text("fresh", encoding="utf-8")
        return CommandResult(command=command, elapsed_s=0.02, stdout="ok", stderr="")

    monkeypatch.setattr("thesis_c.noir.package_manager._run", fake_run_execute)
    execute_witness_isolated(
        package,
        witness_name="poseidon2_memory_0__poseidon2__ultra_honk__fixedrun_witness",
        run_dir=run_dir,
    )


def test_unexpected_names_are_rejected(tmp_path: Path, monkeypatch) -> None:
    package_dir = tmp_path / "circuits_poseidon2"
    package_dir.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    package = CircuitPackage(
        statement="account_inclusion",
        hash_name="poseidon2",
        package_dir=package_dir,
        nargo_package_name="../escape",
        expected_circuit_json=target_dir / "escape.json",
    )

    with pytest.raises(ValueError, match="Invalid package name"):
        compile_isolated(package, run_dir=run_dir)

    package = CircuitPackage(
        statement="eoa_activity_anchored_poseidon2",
        hash_name="poseidon2",
        package_dir=package_dir,
        nargo_package_name="thesis_c_circuits_eoa_activity_anchored_poseidon2",
        expected_circuit_json=target_dir / "thesis_c_circuits_eoa_activity_anchored_poseidon2.json",
    )

    with pytest.raises(ValueError, match="Invalid witness name"):
        execute_witness_isolated(package, witness_name="../escape", run_dir=run_dir)
