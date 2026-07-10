from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import pytest

from thesis_c.backends.base import BackendRunResult
from thesis_c.benchmark import runner as benchmark_runner
from thesis_c.benchmark.runner import BenchmarkConfig, run_benchmarks
from thesis_c.noir.artifacts import CircuitPackage, RunIdentity
from thesis_c.noir.package_manager import CommandResult
from thesis_c.proof_inputs.schema import (
    AccountLeaf,
    BaselineVerificationResult,
    PreparedStatement,
    ProofPayload,
)


class FakeStatement:
    required_payloads = 1

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        payload = payloads[0]
        return PreparedStatement(
            statement_name="account_inclusion",
            public_inputs={
                "public_account_address": payload.address,
                "public_hash_variant_id": 1,
            },
            private_inputs={"private_path_nibbles": [1, 2, 3, 4]},
            metadata={"source_file": payload.source_file, "source_index": payload.source_index},
        )


def _payload() -> ProofPayload:
    return ProofPayload(
        address="0x1111111111111111111111111111111111111111",
        balance="0x01",
        code_hash="0x" + "22" * 32,
        nonce="0x02",
        storage_hash="0x" + "33" * 32,
        account_proof=["0x01"],
        storage_proof=[],
        block_number=9,
        state_root="0x" + "44" * 32,
        source_file=None,
        source_index=0,
    )


def _baseline(payload: ProofPayload, hash_name: str = "keccak256") -> BaselineVerificationResult:
    return BaselineVerificationResult(
        ok=True,
        address=payload.address,
        hash_name=hash_name,
        state_root=payload.state_root or "0x" + "44" * 32,
        leaf=AccountLeaf(
            nonce=2,
            balance=1,
            storage_root="0x" + "55" * 32,
            code_hash="0x" + "22" * 32,
            rlp_hex="0x80",
        ),
        account_proof_node_count=4,
        storage_proof_node_count=0,
        raw_proof_byte_size=1104,
    )


def _fixed_inputs() -> dict[str, object]:
    return {
        "private_path_nibbles": [1, 2, 3, 4],
        "public_account_address": "0x1111111111111111111111111111111111111111",
        "public_hash_variant_id": 1,
        "public_state_root": "0x" + "44" * 32,
    }


def _fixed_run_identity(hash_name: str = "keccak256") -> RunIdentity:
    package_name = (
        "thesis_c_circuits_poseidon2"
        if hash_name == "poseidon2"
        else "thesis_c_circuits"
    )
    package_path = "circuits_poseidon2" if hash_name == "poseidon2" else "circuits"
    return RunIdentity(
        run_id=f"memory_0__{hash_name}__ultra_honk__fixedrun",
        content_hash="0" * 64,
        content_hash_inputs={
            "backend_name": "ultra_honk",
            "circuit_package_identifier": package_name,
            "circuit_package_path": package_path,
            "dataset_id": "memory_0",
            "hash_name": hash_name,
            "nargo_package_name": package_name,
            "oracle_hash": "keccak",
            "prover_toml_sha256": "fixed",
            "scheme": "ultra_honk",
            "source_proof_path": "memory",
            "source_proof_sha256": "",
            "statement": "account_inclusion",
        },
    )


def _setup_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    hash_name: str = "keccak256",
    failure_phase: str | None = None,
    precreate_run_dir: bool = False,
    statements: list[str] | None = None,
    verify_exception: Exception | None = None,
):
    root = tmp_path
    monkeypatch.chdir(root)

    input_path = root / "input.json"
    input_path.write_text("{}", encoding="utf-8")

    package_dir = root / ("circuits_poseidon2" if hash_name == "poseidon2" else "circuits")
    package_dir.mkdir()
    target_dir = root / "target"
    target_dir.mkdir()
    artifact_root = root / "artifacts"
    package_prover_toml = package_dir / "Prover.toml"
    package_prover_toml.write_text("sentinel-package\n", encoding="utf-8")

    payload = _payload()
    baseline = _baseline(payload, hash_name=hash_name)
    run_identity = _fixed_run_identity(hash_name)
    run_dir = (
        artifact_root
        / "account_inclusion"
        / hash_name
        / "ultra_honk"
        / run_identity.run_id
    )
    if precreate_run_dir:
        run_dir.mkdir(parents=True)

    circuit_package = CircuitPackage(
        statement="account_inclusion",
        hash_name=hash_name,
        package_dir=package_dir,
        nargo_package_name="thesis_c_circuits"
        if hash_name == "keccak256"
        else "thesis_c_circuits_poseidon2",
        expected_circuit_json=target_dir
        / (
            "thesis_c_circuits.json"
            if hash_name == "keccak256"
            else "thesis_c_circuits_poseidon2.json"
        ),
    )

    def fake_load_proof_path(path):
        return [payload]

    def fake_verify_account_payload(payload_arg, hash_variant):
        if verify_exception is not None:
            raise verify_exception
        return baseline

    def fake_resolve_circuit_package(statement, resolved_hash_name, repo_root="."):
        assert statement == "account_inclusion"
        assert resolved_hash_name == hash_name
        return circuit_package

    def fake_build_run_identity(**kwargs):
        return run_identity

    def fake_to_noir_input_map(prepared):
        return _fixed_inputs()

    def fake_build_backend(name, bb_binary, oracle_hash):
        class FakeBackend:
            def __init__(self) -> None:
                self.name = name
                self.config = SimpleNamespace(binary=bb_binary, scheme="ultra_honk")

            def prove_and_verify(self, circuit_json, witness_gz, output_dir):
                output_dir = Path(output_dir)
                vk_dir = output_dir / "vk"
                proof_dir = output_dir / "proof"
                public_inputs = output_dir / "public_inputs"
                if failure_phase == "prove":
                    vk_dir.mkdir(parents=True, exist_ok=True)
                    (vk_dir / "vk").write_text("vk", encoding="utf-8")
                    (vk_dir / "vk_hash").write_text("vk_hash", encoding="utf-8")
                    raise RuntimeError("proving failed: simulated")
                if failure_phase == "verify":
                    vk_dir.mkdir(parents=True, exist_ok=True)
                    (vk_dir / "vk").write_text("vk", encoding="utf-8")
                    (vk_dir / "vk_hash").write_text("vk_hash", encoding="utf-8")
                    proof_dir.mkdir(parents=True, exist_ok=True)
                    (proof_dir / "proof").write_text("proof", encoding="utf-8")
                    public_inputs.write_text("public_inputs", encoding="utf-8")
                    raise RuntimeError("verification failed: simulated")

                vk_dir.mkdir(parents=True, exist_ok=True)
                (vk_dir / "vk").write_text("vk", encoding="utf-8")
                (vk_dir / "vk_hash").write_text("vk_hash", encoding="utf-8")
                proof_dir.mkdir(parents=True, exist_ok=True)
                (proof_dir / "proof").write_text("proof", encoding="utf-8")
                public_inputs.write_text("public_inputs", encoding="utf-8")
                return BackendRunResult(
                    backend_name=name,
                    prove_elapsed_s=0.31,
                    verify_elapsed_s=0.17,
                    prove_peak_memory_bytes=1234,
                    verify_peak_memory_bytes=567,
                    proof_path=proof_dir / "proof",
                    vk_path=vk_dir / "vk",
                    public_inputs_path=public_inputs,
                    proof_size_bytes=(proof_dir / "proof").stat().st_size,
                    verification_ok=True,
                    prove_stdout="prove ok",
                    prove_stderr="",
                    verify_stdout="verify ok",
                    verify_stderr="",
                )

        return FakeBackend()

    def fake_compile_isolated(circuit_package_arg, *, run_dir):
        if failure_phase == "compile":
            raise RuntimeError("compile failed: simulated")
        run_dir = Path(run_dir)
        (run_dir / "circuit.json").write_text('{"num_constraints": 7}', encoding="utf-8")
        return CommandResult(
            command=["nargo", "compile", "--program-dir", str(circuit_package_arg.package_dir)],
            elapsed_s=0.11,
            stdout="compile ok",
            stderr="",
        )

    def fake_execute_witness_isolated(circuit_package_arg, *, witness_name, run_dir):
        if failure_phase == "execute_witness":
            raise RuntimeError("execute witness failed: simulated")
        run_dir = Path(run_dir)
        (run_dir / "witness.gz").write_text("witness", encoding="utf-8")
        return CommandResult(
            command=[
                "nargo",
                "execute",
                witness_name,
                "--program-dir",
                str(circuit_package_arg.package_dir),
            ],
            elapsed_s=0.22,
            stdout="execute ok",
            stderr="",
        )

    class FakeStatement:
        required_payloads = 1

        def prepare(self, payloads, baseline_results):
            return PreparedStatement(
                statement_name="account_inclusion",
                public_inputs={
                    "public_account_address": payloads[0].address,
                    "public_hash_variant_id": 1,
                },
                private_inputs={"private_path_nibbles": [1, 2, 3, 4]},
                metadata={"source_file": payloads[0].source_file, "source_index": payloads[0].source_index},
            )

    monkeypatch.setattr(benchmark_runner, "load_proof_path", fake_load_proof_path)
    monkeypatch.setattr(benchmark_runner, "verify_account_payload", fake_verify_account_payload)
    monkeypatch.setattr(benchmark_runner, "resolve_circuit_package", fake_resolve_circuit_package)
    monkeypatch.setattr(benchmark_runner, "build_run_identity", fake_build_run_identity)
    monkeypatch.setattr(benchmark_runner, "to_noir_input_map", fake_to_noir_input_map)
    monkeypatch.setattr(benchmark_runner, "_build_backend", fake_build_backend)
    monkeypatch.setattr(benchmark_runner, "compile_isolated", fake_compile_isolated)
    monkeypatch.setattr(benchmark_runner, "execute_witness_isolated", fake_execute_witness_isolated)
    monkeypatch.setattr(benchmark_runner, "STATEMENT_REGISTRY", {"account_inclusion": FakeStatement})

    config = BenchmarkConfig(
        input_path=input_path,
        circuits_dir=package_dir,
        output_dir=root / "benchmarks",
        hashes=[hash_name],
        backends=["ultra_honk"],
        statements=statements or ["account_inclusion"],
        input_path_keccak=input_path,
        input_path_poseidon2=input_path,
        artifact_root=artifact_root,
    )
    return config, run_dir, package_prover_toml, payload


def _read_metadata(run_dir: Path) -> dict:
    return __import__("json").loads((run_dir / "metadata.json").read_text(encoding="utf-8"))


def test_successful_keccak_isolated_benchmark_writes_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config, run_dir, _, _ = _setup_harness(tmp_path, monkeypatch, hash_name="keccak256")

    rows = run_benchmarks(config)

    assert len(rows) == 1
    assert rows[0].status == "ok"
    assert rows[0].verification_ok is True

    metadata = _read_metadata(run_dir)
    assert metadata["status"] == "verified"
    assert metadata["witness_name"] == "keccak256_memory_0__keccak256__ultra_honk__fixedrun_witness"
    assert metadata["artifact_paths"]["circuit_json"] == str(
        Path("artifacts/account_inclusion/keccak256/ultra_honk/memory_0__keccak256__ultra_honk__fixedrun/circuit.json")
    )
    assert metadata["artifact_paths"]["witness"] == str(
        Path("artifacts/account_inclusion/keccak256/ultra_honk/memory_0__keccak256__ultra_honk__fixedrun/witness.gz")
    )
    assert metadata["file_sha256"]["prover_toml"]
    assert metadata["file_sha256"]["circuit_json"]
    assert metadata["file_sha256"]["witness_gz"]
    assert metadata["file_sha256"]["proof"]
    assert metadata["file_sha256"]["public_inputs"]
    assert metadata["file_sha256"]["timings"]


@pytest.mark.parametrize(
    "failure_phase, expected_failed_phase",
    [
        ("compile", "compile"),
        ("execute_witness", "execute_witness"),
        ("prove", "prove"),
        ("verify", "verify"),
    ],
)
def test_failed_runs_write_failure_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
    expected_failed_phase: str,
) -> None:
    config, run_dir, _, _ = _setup_harness(
        tmp_path,
        monkeypatch,
        hash_name="keccak256",
        failure_phase=failure_phase,
    )

    rows = run_benchmarks(config)

    assert len(rows) == 1
    assert rows[0].status == "error"

    metadata = _read_metadata(run_dir)
    assert metadata["status"] == "failed"
    assert metadata["failed_phase"] == expected_failed_phase
    assert metadata["error_type"] == "RuntimeError"
    assert "simulated" in metadata["error_message"]
    assert metadata["witness_name"] == "keccak256_memory_0__keccak256__ultra_honk__fixedrun_witness"
    assert metadata["artifact_paths"]["package_prover_toml"]
    assert metadata["artifact_paths"]["run_prover_toml"]
    assert metadata["timings"] is not None


def test_existing_run_dir_does_not_modify_package_prover_toml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, run_dir, package_prover_toml, _ = _setup_harness(
        tmp_path,
        monkeypatch,
        hash_name="keccak256",
        precreate_run_dir=True,
    )

    before = package_prover_toml.read_text(encoding="utf-8")

    rows = run_benchmarks(config)

    after = package_prover_toml.read_text(encoding="utf-8")
    assert before == after
    assert not (run_dir / "metadata.json").exists()
    assert rows[0].status == "error"


def test_legacy_latest_file_helper_is_removed() -> None:
    assert not hasattr(benchmark_runner, "compile_and_execute")
    from thesis_c.noir import package_manager

    assert not hasattr(package_manager, "compile_and_execute")
    assert not hasattr(package_manager, "_latest_file")


def test_poseidon2_account_inclusion_uses_real_isolated_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, run_dir, _, _ = _setup_harness(tmp_path, monkeypatch, hash_name="poseidon2")

    rows = run_benchmarks(config)

    assert len(rows) == 1
    assert rows[0].status == "ok"
    assert rows[0].verification_ok is True
    assert rows[0].error is None

    metadata = _read_metadata(run_dir)
    assert metadata["status"] == "verified"
    assert metadata["hash_name"] == "poseidon2"
    assert metadata["nargo_package_name"] == "thesis_c_circuits_poseidon2"
    assert metadata["package_dir"].endswith("circuits_poseidon2")
    assert metadata["witness_name"] == (
        "poseidon2_memory_0__poseidon2__ultra_honk__fixedrun_witness"
    )


def test_poseidon2_missing_adapter_is_error_not_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, run_dir, _, _ = _setup_harness(
        tmp_path,
        monkeypatch,
        hash_name="poseidon2",
        verify_exception=RuntimeError(
            "Poseidon2 digest adapter is not configured. "
            "Set THESIS_C_POSEIDON2_CMD or THESIS_C_POSEIDON2_VECTORS."
        ),
    )

    rows = run_benchmarks(config)

    assert len(rows) == 1
    assert rows[0].status == "error"
    assert rows[0].error is not None
    assert "Poseidon2 digest adapter is not configured" in rows[0].error
    assert "proxy" not in rows[0].error
    assert not (run_dir / "metadata.json").exists()


def test_poseidon2_mixed_statement_missing_adapter_keeps_unsupported_statement_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, run_dir, _, _ = _setup_harness(
        tmp_path,
        monkeypatch,
        hash_name="poseidon2",
        statements=["storage_slot_membership", "account_inclusion"],
        verify_exception=RuntimeError(
            "Poseidon2 digest adapter is not configured. "
            "Set THESIS_C_POSEIDON2_CMD or THESIS_C_POSEIDON2_VECTORS."
        ),
    )

    rows = run_benchmarks(config)

    assert len(rows) == 2
    by_statement = {row.statement: row for row in rows}
    assert by_statement["storage_slot_membership"].status == "proxy"
    assert (
        by_statement["storage_slot_membership"].error
        == "proxy_poseidon2_statement_not_in_circuit"
    )
    assert by_statement["account_inclusion"].status == "error"
    assert by_statement["account_inclusion"].error is not None
    assert "Poseidon2 digest adapter is not configured" in by_statement["account_inclusion"].error
    assert not (run_dir / "metadata.json").exists()


def test_unsupported_poseidon2_statement_remains_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, run_dir, _, _ = _setup_harness(
        tmp_path,
        monkeypatch,
        hash_name="poseidon2",
        statements=["storage_slot_membership"],
    )

    monkeypatch.setattr(
        benchmark_runner,
        "compile_isolated",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("compile path should not run")),
    )
    monkeypatch.setattr(
        benchmark_runner,
        "execute_witness_isolated",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("execute path should not run")),
    )
    monkeypatch.setattr(
        benchmark_runner,
        "_build_backend",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("backend path should not run")),
    )

    rows = run_benchmarks(config)

    assert len(rows) == 1
    assert rows[0].status == "proxy"
    assert rows[0].error == "proxy_poseidon2_statement_not_in_circuit"
    assert not (run_dir / "metadata.json").exists()
