from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from thesis_c.benchmark.csv_writer import write_csv
from thesis_c.benchmark.json_writer import write_json as write_benchmark_json
from thesis_c.benchmark.metrics import BenchmarkRecord
from thesis_c.benchmark.runner import BenchmarkConfig, run_benchmarks
from thesis_c.noir.artifacts import resolve_circuit_package, safe_filename, write_json
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.proof_inputs.normalizer import (
    account_proof_node_count,
    raw_proof_byte_size,
    storage_proof_node_count,
)


EXPECTED_REPO_REVISION = "0d8bf3d9554136d599a116c40a525b8a29b84a17"
EXPECTED_NARGO_VERSION = "1.0.0-beta.22"
EXPECTED_BB_VERSION = "5.0.0-nightly.20260522"
EXPECTED_POSEIDON2_DEPENDENCY_REVISION = "56f8b45745ebebb0b788d26867e7a89b7363ced7"
MIN_FREE_DISK_BYTES = 5 * 1024**3

REQUIRED_PYTHON_IMPORTS = ["pytest", "psutil", "pandas", "matplotlib"]
REQUIRED_CRS_FILES = (
    "bn254_g1_compressed.dat",
    "bn254_g2.dat",
    "grumpkin_g1.flat.dat",
)


@dataclass(frozen=True, slots=True)
class PortableEnvironment:
    thesis_root: Path
    repo_root: Path
    python_bin: Path
    nargo_bin: Path
    bb_bin: Path
    poseidon2_cmd: str
    home: Path
    nargo_home: Path
    xdg_cache_home: Path
    cargo_home: Path
    crs_path: Path
    expected_repo_revision: str = EXPECTED_REPO_REVISION
    expected_nargo_version: str = EXPECTED_NARGO_VERSION
    expected_bb_version: str = EXPECTED_BB_VERSION
    expected_poseidon2_dependency_revision: str = EXPECTED_POSEIDON2_DEPENDENCY_REVISION


@dataclass(frozen=True, slots=True)
class PortableRowSpec:
    label: str
    statement: str
    hash_name: str
    input_path: Path
    input_path_keccak: Path | None = None
    input_path_poseidon2: Path | None = None
    anchored: bool = False
    allow_synthetic: bool = False
    expected_payload_count: int = 1
    expected_result_count: int | None = None


def _sha256_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return value


def _command_output(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip()
    if completed.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(command)}\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return output


def _command_output_allow_failure(command: list[str], *, cwd: Path | None = None) -> tuple[int, str]:
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, (completed.stdout + completed.stderr).strip()


def _parse_version(text: str) -> str:
    for token in text.replace("(", " ").replace(")", " ").split():
        if token[0].isdigit():
            return token
    return text.strip()


def _resolve_env_path(env: Mapping[str, str], name: str, default: Path | None = None) -> Path:
    raw = env.get(name, "").strip()
    if raw:
        return Path(raw).expanduser()
    if default is None:
        raise ValueError(f"Missing required environment variable: {name}")
    return default


def _resolve_executable(env: Mapping[str, str], name: str, *, default: Path | None = None) -> Path:
    raw = env.get(name, "").strip()
    if raw:
        path = Path(raw).expanduser()
    elif default is not None:
        path = default
    else:
        resolved = shutil.which(name.lower().replace("_bin", ""))
        if resolved:
            path = Path(resolved)
        else:
            raise ValueError(f"Missing required environment variable: {name}")
    if not path.exists():
        raise FileNotFoundError(f"Executable not found: {path}")
    if not os.access(path, os.X_OK):
        raise PermissionError(f"Executable is not runnable: {path}")
    return path


def _resolve_poseidon2_cmd(env: Mapping[str, str], thesis_root: Path) -> str:
    raw = env.get("POSEIDON2_CMD", "").strip()
    if raw:
        command = raw
    else:
        candidate = (
            thesis_root
            / "besu_bonsai"
            / "ethereum"
            / "trie"
            / "build"
            / "install"
            / "besu-poseidon2-hash"
            / "bin"
            / "besu-poseidon2-hash"
        )
        if not candidate.exists():
            raise FileNotFoundError(
                "POSEIDON2_CMD is unset and the default helper binary does not exist."
            )
        command = f"{candidate} {{hex0x}}"
    if "{hex0x}" not in command:
        raise ValueError("POSEIDON2_CMD must contain the '{hex0x}' placeholder.")
    executable = shlex.split(command)[0]
    executable_path = Path(executable)
    if not executable_path.exists():
        raise FileNotFoundError(f"Poseidon2 helper executable not found: {executable_path}")
    if not os.access(executable_path, os.X_OK):
        raise PermissionError(f"Poseidon2 helper executable is not runnable: {executable_path}")
    return command


def derive_environment(env: Mapping[str, str] | None = None) -> PortableEnvironment:
    source = env or os.environ
    thesis_root = _resolve_env_path(source, "THESIS_ROOT")
    repo_root = thesis_root / "SNARK" / "thesis_c"
    python_bin = _resolve_executable(
        source,
        "PYTHON_BIN",
        default=thesis_root / ".venv" / "bin" / "python",
    )
    nargo_bin = _resolve_executable(
        source,
        "NARGO_BIN",
        default=Path(shutil.which("nargo")) if shutil.which("nargo") else None,
    )
    bb_bin = _resolve_executable(
        source,
        "BB_BIN",
        default=(Path.home() / ".bb" / "bb" if (Path.home() / ".bb" / "bb").exists() else None),
    )
    poseidon2_cmd = _resolve_poseidon2_cmd(source, thesis_root)
    home = _resolve_env_path(source, "HOME", default=thesis_root)
    nargo_home = _resolve_env_path(source, "NARGO_HOME", default=thesis_root / "nargo")
    xdg_cache_home = _resolve_env_path(source, "XDG_CACHE_HOME", default=thesis_root / ".cache")
    cargo_home = _resolve_env_path(source, "CARGO_HOME", default=thesis_root / ".cargo")
    crs_path = _resolve_env_path(source, "CRS_PATH", default=thesis_root / ".bb-crs")
    return PortableEnvironment(
        thesis_root=thesis_root,
        repo_root=repo_root,
        python_bin=python_bin,
        nargo_bin=nargo_bin,
        bb_bin=bb_bin,
        poseidon2_cmd=poseidon2_cmd,
        home=home,
        nargo_home=nargo_home,
        xdg_cache_home=xdg_cache_home,
        cargo_home=cargo_home,
        crs_path=crs_path,
        expected_repo_revision=source.get("EXPECTED_REPO_REVISION", EXPECTED_REPO_REVISION),
        expected_nargo_version=source.get("EXPECTED_NARGO_VERSION", EXPECTED_NARGO_VERSION),
        expected_bb_version=source.get("EXPECTED_BB_VERSION", EXPECTED_BB_VERSION),
        expected_poseidon2_dependency_revision=source.get(
            "EXPECTED_POSEIDON2_DEPENDENCY_REVISION",
            EXPECTED_POSEIDON2_DEPENDENCY_REVISION,
        ),
    )


def _tool_version(path: Path, args: list[str] | None = None) -> str:
    command = [str(path), *(args or ["--version"])]
    return _parse_version(_command_output(command))


def _git_command(repo_root: Path, *args: str) -> str:
    return _command_output(["git", "-C", str(repo_root), *args])


def _git_sha(repo_root: Path, *args: str) -> str:
    return _git_command(repo_root, *args).strip()


def _git_dirty_info(repo_root: Path) -> dict[str, Any]:
    status = _git_command(repo_root, "status", "--porcelain")
    dirty = bool(status.strip())
    diff = _command_output(["git", "-C", str(repo_root), "diff", "--binary", "--no-color", "HEAD"])
    return {
        "dirty": dirty,
        "status_porcelain": status.splitlines(),
        "diff_sha256": _sha256_bytes(diff.encode("utf-8")),
        "diff_line_count": len(diff.splitlines()),
    }


def _poseidon2_dependency_root(env: PortableEnvironment) -> Path:
    candidate = env.thesis_root / "besu_bonsai"
    if not candidate.exists():
        raise FileNotFoundError(
            f"Poseidon2 dependency tree not found at {candidate}. "
            "Copy or clone the pinned besu_bonsai tree alongside THESIS_ROOT."
        )
    return candidate


def _system_metadata() -> dict[str, Any]:
    cpu = None
    memory_bytes = None
    try:
        cpu = _command_output(["sysctl", "-n", "machdep.cpu.brand_string"])
    except Exception:
        cpu = platform.processor() or platform.machine()
    try:
        memory_bytes = int(_command_output(["sysctl", "-n", "hw.memsize"]))
    except Exception:
        memory_bytes = None
    return {
        "hostname": socket.gethostname(),
        "architecture": platform.machine(),
        "cpu": cpu,
        "physical_memory_bytes": memory_bytes,
        "os_version": platform.mac_ver()[0] or platform.platform(),
    }


def _free_disk_bytes(path: Path) -> int:
    usage = shutil.disk_usage(path)
    return usage.free


def _require_imports() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in REQUIRED_PYTHON_IMPORTS:
        module = importlib.import_module(name)
        versions[name] = getattr(module, "__version__", "imported")
    return versions


def validate_toolchain(env: PortableEnvironment) -> dict[str, Any]:
    return _validation_common(env)


def _row_path(env: PortableEnvironment, statement: str, hash_name: str, backend_name: str, run_id: str) -> Path:
    return (
        env.repo_root
        / "benchmarks"
        / "runs"
        / safe_filename(run_id)
        / "artifacts"
        / safe_filename(statement)
        / safe_filename(hash_name)
        / safe_filename(backend_name)
        / safe_filename(run_id)
    )


def _fixture_checksum(path: Path) -> str:
    return _sha256_file(path)


def build_full_row_specs(env: PortableEnvironment) -> list[PortableRowSpec]:
    root = env.repo_root
    thesis_root = env.thesis_root
    return [
        PortableRowSpec(
            label="account_inclusion_keccak_supplied_root",
            statement="account_inclusion",
            hash_name="keccak256",
            input_path=thesis_root / "sample_proofs" / "proof_keccak_forest.json",
        ),
        PortableRowSpec(
            label="account_inclusion_poseidon2_supplied_root",
            statement="account_inclusion",
            hash_name="poseidon2",
            input_path=root / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json",
            input_path_poseidon2=root / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json",
        ),
        PortableRowSpec(
            label="account_inclusion_keccak_anchored",
            statement="account_inclusion_anchored",
            hash_name="keccak256",
            input_path=root / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json",
            input_path_keccak=root / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json",
            anchored=True,
        ),
        PortableRowSpec(
            label="account_inclusion_poseidon2_anchored",
            statement="account_inclusion_anchored_poseidon2",
            hash_name="poseidon2",
            input_path=root / "datasets" / "poseidon2" / "hoodi_block_9_anchored_account_proof_poseidon2.json",
            input_path_poseidon2=root / "datasets" / "poseidon2" / "hoodi_block_9_anchored_account_proof_poseidon2.json",
            anchored=True,
        ),
        PortableRowSpec(
            label="balance_keccak_supplied_root",
            statement="balance_verification",
            hash_name="keccak256",
            input_path=thesis_root / "sample_proofs" / "proof_keccak_forest.json",
            input_path_keccak=thesis_root / "sample_proofs" / "proof_keccak_forest.json",
        ),
        PortableRowSpec(
            label="balance_poseidon2_supplied_root",
            statement="balance_verification",
            hash_name="poseidon2",
            input_path=root / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json",
            input_path_poseidon2=root / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json",
        ),
        PortableRowSpec(
            label="balance_keccak_anchored",
            statement="balance_verification_anchored",
            hash_name="keccak256",
            input_path=root / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json",
            input_path_keccak=root / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json",
            anchored=True,
        ),
        PortableRowSpec(
            label="balance_poseidon2_anchored",
            statement="balance_verification_anchored_poseidon2",
            hash_name="poseidon2",
            input_path=root / "datasets" / "poseidon2" / "hoodi_block_9_anchored_account_proof_poseidon2.json",
            input_path_poseidon2=root / "datasets" / "poseidon2" / "hoodi_block_9_anchored_account_proof_poseidon2.json",
            anchored=True,
        ),
        PortableRowSpec(
            label="codehash_keccak_supplied_root",
            statement="codehash_verification",
            hash_name="keccak256",
            input_path=thesis_root / "sample_proofs" / "proof_keccak_forest.json",
            input_path_keccak=thesis_root / "sample_proofs" / "proof_keccak_forest.json",
        ),
        PortableRowSpec(
            label="codehash_poseidon2_supplied_root",
            statement="codehash_verification",
            hash_name="poseidon2",
            input_path=root / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json",
            input_path_poseidon2=root / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json",
        ),
        PortableRowSpec(
            label="codehash_keccak_anchored",
            statement="codehash_verification_anchored",
            hash_name="keccak256",
            input_path=root / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json",
            input_path_keccak=root / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json",
            anchored=True,
        ),
        PortableRowSpec(
            label="codehash_poseidon2_anchored",
            statement="codehash_verification_anchored_poseidon2",
            hash_name="poseidon2",
            input_path=root / "datasets" / "poseidon2" / "hoodi_block_9_anchored_account_proof_poseidon2.json",
            input_path_poseidon2=root / "datasets" / "poseidon2" / "hoodi_block_9_anchored_account_proof_poseidon2.json",
            anchored=True,
        ),
        PortableRowSpec(
            label="eoa_activity_keccak_supplied_root",
            statement="eoa_activity",
            hash_name="keccak256",
            input_path=root / "datasets" / "eoa_activity" / "controlled_keccak_eoa_activity_mixed_depth3_4.json",
            input_path_keccak=root / "datasets" / "eoa_activity" / "controlled_keccak_eoa_activity_mixed_depth3_4.json",
            expected_payload_count=2,
            expected_result_count=1,
        ),
        PortableRowSpec(
            label="eoa_activity_poseidon2_supplied_root",
            statement="eoa_activity",
            hash_name="poseidon2",
            input_path=root / "datasets" / "eoa_activity" / "controlled_poseidon2_eoa_activity_mixed_depth2_4.json",
            input_path_poseidon2=root / "datasets" / "eoa_activity" / "controlled_poseidon2_eoa_activity_mixed_depth2_4.json",
            expected_payload_count=2,
            expected_result_count=1,
        ),
    ]


def build_smoke_row_specs(env: PortableEnvironment) -> list[PortableRowSpec]:
    full = build_full_row_specs(env)
    wanted = {
        "account_inclusion_keccak_supplied_root",
        "account_inclusion_poseidon2_supplied_root",
        "account_inclusion_keccak_anchored",
        "balance_poseidon2_anchored",
    }
    return [row for row in full if row.label in wanted]


def validate_fixture_inventory(env: PortableEnvironment, row_specs: list[PortableRowSpec]) -> dict[str, Any]:
    fixture_records: list[dict[str, Any]] = []
    for spec in row_specs:
        payloads = load_proof_path(spec.input_path)
        if len(payloads) != spec.expected_payload_count:
            raise RuntimeError(
                f"Fixture payload count mismatch for {spec.label}: expected {spec.expected_payload_count}, got {len(payloads)}"
            )
        raw_text = spec.input_path.read_text(encoding="utf-8")
        raw = json.loads(raw_text)
        if spec.statement == "eoa_activity":
            items = raw if isinstance(raw, list) else [raw]
            if any(item.get("synthetic_fixture", False) for item in items if isinstance(item, dict)):
                raise RuntimeError(f"Synthetic EOA fixture selected for {spec.label}: {spec.input_path}")
            if any(
                not isinstance(item, dict)
                or not item.get("controlled_besu_state", False)
                or "real controlled Besu paired fixture" not in str(item.get("fixture_classification", ""))
                for item in items
            ):
                raise RuntimeError(f"Non-real EOA fixture selected for {spec.label}: {spec.input_path}")
        if spec.anchored:
            payload = payloads[0]
            header_anchor = payload.raw_result.get("header_anchor")
            if not isinstance(header_anchor, dict):
                raise RuntimeError(f"Anchored fixture missing header_anchor metadata: {spec.input_path}")
            required_keys = {
                "block_hash",
                "state_root",
                "header_rlp_len",
                "header_field_count",
                "header_rlp_source",
                "header_hash_function",
                "source_reference",
            }
            if not required_keys.issubset(header_anchor):
                missing = ", ".join(sorted(required_keys - set(header_anchor)))
                raise RuntimeError(f"Anchored fixture missing required metadata ({missing}): {spec.input_path}")
        fixture_records.append(
            {
                "label": spec.label,
                "statement": spec.statement,
                "hash_name": spec.hash_name,
                "path": str(spec.input_path),
                "sha256": _fixture_checksum(spec.input_path),
                "payload_count": len(payloads),
                "anchored": spec.anchored,
            }
        )
    return {"fixtures": fixture_records}


def _row_spec_to_manifest(env: PortableEnvironment, spec: PortableRowSpec) -> dict[str, Any]:
    package = resolve_circuit_package(spec.statement, spec.hash_name, env.repo_root)
    return {
        "label": spec.label,
        "statement": spec.statement,
        "hash_name": spec.hash_name,
        "input_path": str(spec.input_path),
        "input_path_keccak": str(spec.input_path_keccak) if spec.input_path_keccak else None,
        "input_path_poseidon2": str(spec.input_path_poseidon2) if spec.input_path_poseidon2 else None,
        "anchored": spec.anchored,
        "expected_payload_count": spec.expected_payload_count,
        "expected_result_count": (
            spec.expected_result_count
            if spec.expected_result_count is not None
            else spec.expected_payload_count
        ),
        "package_name": package.nargo_package_name,
        "package_dir": str(package.package_dir),
        "circuit_json": str(package.expected_circuit_json),
    }


def build_manifest(
    env: PortableEnvironment,
    *,
    run_id: str,
    row_specs: list[PortableRowSpec],
    toolchain: dict[str, Any],
    fixture_summary: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    row_entries = [_row_spec_to_manifest(env, spec) for spec in row_specs]
    return {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hostname": socket.gethostname(),
        "architecture": platform.machine(),
        "cpu": toolchain["cpu"],
        "physical_memory_bytes": toolchain["physical_memory_bytes"],
        "free_disk_bytes": toolchain["free_disk_bytes"],
        "os_version": toolchain["os_version"],
        "disk_path": toolchain["disk_path"],
        "repository_revision": toolchain["repository_revision"],
        "repo_revision_expected": env.expected_repo_revision,
        "dirty_worktree": toolchain["dirty_worktree"],
        "dirty_worktree_diff_sha256": toolchain["dirty_worktree_diff_sha256"],
        "dirty_worktree_diff_line_count": toolchain["dirty_worktree_diff_line_count"],
        "dirty_worktree_status": toolchain["dirty_worktree_status"],
        "python": {
            "path": str(env.python_bin),
            "version": toolchain["python_version"],
        },
        "nargo": {
            "path": str(env.nargo_bin),
            "version": toolchain["nargo_version"],
            "sha256": toolchain["nargo_sha256"],
        },
        "bb": {
            "path": str(env.bb_bin),
            "version": toolchain["bb_version"],
            "sha256": toolchain["bb_sha256"],
        },
        "poseidon2": {
            "command": env.poseidon2_cmd,
            "executable": toolchain["poseidon2_executable"],
            "sha256": toolchain["poseidon2_sha256"],
            "dependency_revision": toolchain["poseidon2_dependency_revision"],
        },
        "environment": {
            "home": str(env.home),
            "nargo_home": str(env.nargo_home),
            "xdg_cache_home": str(env.xdg_cache_home),
            "cargo_home": str(env.cargo_home),
            "crs_path": str(env.crs_path),
        },
        "crs": toolchain["crs"],
        "fixtures": fixture_summary["fixtures"],
        "rows": row_entries,
        "logical_spec_count": len(row_specs),
        "expected_physical_result_count": sum(_expected_result_count(spec) for spec in row_specs),
        "status": status,
        "hardware_variable_note": (
            "Timings from different laptops should be compared only when machine hardware is treated as an experimental variable."
        ),
    }


def _validation_common(env: PortableEnvironment) -> dict[str, Any]:
    nargo_version = _tool_version(env.nargo_bin)
    bb_version = _tool_version(env.bb_bin)
    python_version = platform.python_version()
    nargo_sha256 = _sha256_file(env.nargo_bin)
    bb_sha256 = _sha256_file(env.bb_bin)
    poseidon2_executable = Path(shlex.split(env.poseidon2_cmd)[0])
    poseidon2_sha256 = _sha256_file(poseidon2_executable)
    poseidon2_dependency_root = _poseidon2_dependency_root(env)
    poseidon2_dependency_revision = _git_sha(poseidon2_dependency_root, "rev-parse", "HEAD")
    if poseidon2_dependency_revision != env.expected_poseidon2_dependency_revision:
        raise RuntimeError(
            "Poseidon2 dependency revision mismatch: "
            f"expected {env.expected_poseidon2_dependency_revision}, got {poseidon2_dependency_revision}."
        )
    repo_revision = _git_sha(env.repo_root, "rev-parse", "HEAD")
    if repo_revision != env.expected_repo_revision:
        raise RuntimeError(
            f"Repository revision mismatch: expected {env.expected_repo_revision}, got {repo_revision}."
        )
    if env.expected_nargo_version not in nargo_version:
        raise RuntimeError(
            f"Nargo version mismatch: expected {env.expected_nargo_version}, got {nargo_version}."
        )
    if env.expected_bb_version not in bb_version:
        raise RuntimeError(
            f"Barretenberg version mismatch: expected {env.expected_bb_version}, got {bb_version}."
        )
    bb_help = _command_output([str(env.bb_bin), "--help"])
    bb_strings_probe = _command_output(["strings", str(env.bb_bin)])
    if "ultra_honk" not in bb_help and "ultra_honk" not in bb_strings_probe:
        raise RuntimeError(
            "BB does not appear to support ultra_honk. The binary does not advertise it."
        )
    dirty = _git_dirty_info(env.repo_root)
    crs_manifest = []
    system = _system_metadata()
    free_disk_bytes = _free_disk_bytes(env.repo_root)
    if free_disk_bytes < MIN_FREE_DISK_BYTES:
        raise RuntimeError(
            f"Insufficient free disk space under {env.repo_root}: "
            f"{free_disk_bytes} bytes available, need at least {MIN_FREE_DISK_BYTES} bytes."
        )
    for rel_name in REQUIRED_CRS_FILES:
        crs_file = env.crs_path / rel_name
        if not crs_file.exists() or crs_file.stat().st_size <= 0:
            raise FileNotFoundError(f"Missing CRS file: {crs_file}")
        crs_manifest.append(
            {
                "path": str(crs_file),
                "size_bytes": crs_file.stat().st_size,
                "sha256": _sha256_file(crs_file),
            }
        )
    return {
        "repository_revision": repo_revision,
        "dirty_worktree": dirty,
        "dirty_worktree_diff_sha256": dirty["diff_sha256"],
        "dirty_worktree_diff_line_count": dirty["diff_line_count"],
        "dirty_worktree_status": dirty["status_porcelain"],
        "python_version": python_version,
        "nargo_version": nargo_version,
        "nargo_sha256": nargo_sha256,
        "bb_version": bb_version,
        "bb_sha256": bb_sha256,
        "poseidon2_executable": str(poseidon2_executable),
        "poseidon2_sha256": poseidon2_sha256,
        "poseidon2_dependency_revision": poseidon2_dependency_revision,
        "crs": crs_manifest,
        "cpu": system["cpu"],
        "physical_memory_bytes": system["physical_memory_bytes"],
        "free_disk_bytes": free_disk_bytes,
        "os_version": system["os_version"],
        "disk_path": str(env.repo_root),
    }


def perform_preflight(env: PortableEnvironment, row_specs: list[PortableRowSpec]) -> dict[str, Any]:
    _require_imports()
    if not env.thesis_root.exists():
        raise FileNotFoundError(f"THESIS_ROOT does not exist: {env.thesis_root}")
    if not env.repo_root.exists():
        raise FileNotFoundError(f"Repository root does not exist: {env.repo_root}")
    for path in [env.nargo_home, env.xdg_cache_home, env.cargo_home, env.crs_path]:
        path.mkdir(parents=True, exist_ok=True)
        if not os.access(path, os.W_OK):
            raise PermissionError(f"Cache path is not writable: {path}")
    if Path(sys.executable).resolve() != Path(env.python_bin).resolve():
        raise RuntimeError(
            f"Running under {sys.executable}, but PYTHON_BIN resolves to {env.python_bin}."
        )
    if env.expected_repo_revision != _git_sha(env.repo_root, "rev-parse", "HEAD"):
        raise RuntimeError(
            f"Repository revision mismatch: expected {env.expected_repo_revision}, got {_git_sha(env.repo_root, 'rev-parse', 'HEAD')}."
        )
    toolchain = _validation_common(env)
    fixture_summary = validate_fixture_inventory(env, row_specs)
    return build_manifest(
        env,
        run_id="preflight",
        row_specs=row_specs,
        toolchain=toolchain,
        fixture_summary=fixture_summary,
        status="preflight-ok",
    )


def _run_single_row(env: PortableEnvironment, spec: PortableRowSpec, *, run_id: str, run_root: Path) -> list[Any]:
    artifact_root = run_root / "artifacts"
    output_dir = run_root
    config = BenchmarkConfig(
        input_path=spec.input_path,
        circuits_dir=env.repo_root,
        output_dir=output_dir,
        hashes=[spec.hash_name],
        backends=["ultra_honk"],
        statements=[spec.statement],
        input_path_keccak=spec.input_path_keccak,
        input_path_poseidon2=spec.input_path_poseidon2,
        bb_binary=str(env.bb_bin),
        bb_oracle_hash="keccak",
        artifact_root=artifact_root,
        proving_system="ultra_honk",
    )
    return run_benchmarks(config)


def _physical_result_id(row: Any) -> str:
    dataset_id = getattr(row, "dataset_id", "unknown")
    return "::".join(
        [
            str(row.statement),
            str(row.hash_name),
            str(row.backend),
            str(dataset_id),
        ]
    )


def _expected_result_count(spec: PortableRowSpec) -> int:
    return spec.expected_result_count if spec.expected_result_count is not None else spec.expected_payload_count


def _validate_and_annotate_rows(spec: PortableRowSpec, rows: list[Any]) -> list[Any]:
    expected = _expected_result_count(spec)
    if len(rows) != expected:
        raise RuntimeError(
            f"Expected {expected} result row(s) for {spec.label}, got {len(rows)}"
        )

    result_ids = [_physical_result_id(row) for row in rows]
    if len(set(result_ids)) != len(result_ids):
        raise RuntimeError(f"Duplicate physical result identity for {spec.label}")

    annotated: list[Any] = []
    for payload_index, row in enumerate(rows):
        if isinstance(row, BenchmarkRecord):
            extras = dict(row.extras or {})
            extras.update(
                {
                    "logical_spec_label": spec.label,
                    "payload_index": payload_index,
                    "expected_payload_count": spec.expected_payload_count,
                    "expected_result_count": expected,
                    "physical_result_id": result_ids[payload_index],
                }
            )
            row = replace(row, extras=extras)
        annotated.append(row)
    return annotated


def _attempt_record(spec: PortableRowSpec, row: Any, *, run_dir: Path) -> dict[str, Any]:
    return {
        "label": spec.label,
        "statement": row.statement,
        "hash_name": row.hash_name,
        "backend": row.backend,
        "dataset_id": getattr(row, "dataset_id", None),
        "physical_result_id": _physical_result_id(row),
        "status": row.status,
        "verification_ok": row.verification_ok,
        "error": row.error,
        "run_dir": str(run_dir),
    }


def run_matrix(
    env: PortableEnvironment,
    *,
    run_id: str,
    row_specs: list[PortableRowSpec],
) -> tuple[list[Any], dict[str, Any]]:
    run_root = env.repo_root / "benchmarks" / "runs" / safe_filename(run_id)
    run_root.mkdir(parents=True, exist_ok=False)
    toolchain = _validation_common(env)
    fixture_summary = validate_fixture_inventory(env, row_specs)

    all_rows: list[Any] = []
    attempts: list[dict[str, Any]] = []
    for spec in row_specs:
        row_root = run_root / "rows" / safe_filename(spec.label)
        row_root.mkdir(parents=True, exist_ok=False)
        rows = _validate_and_annotate_rows(
            spec,
            _run_single_row(env, spec, run_id=run_id, run_root=row_root),
        )
        all_rows.extend(rows)
        attempts.extend(_attempt_record(spec, row, run_dir=row_root) for row in rows)

    write_csv(run_root / "benchmark.csv", all_rows)
    write_benchmark_json(run_root / "benchmark.json", all_rows)
    summary = {
        "run_id": run_id,
        "rows_total": len(all_rows),
        "rows_ok": sum(1 for row in all_rows if row.status == "ok" and row.verification_ok),
        "rows_failed": sum(1 for row in all_rows if row.status != "ok" or not row.verification_ok),
        "logical_specs_total": len(row_specs),
        "logical_specs_ok": sum(
            1
            for spec in row_specs
            if any(
                getattr(row, "extras", None)
                and row.extras.get("logical_spec_label") == spec.label
                for row in all_rows
            )
            and all(
                row.status == "ok"
                and row.verification_ok
                for row in all_rows
                if getattr(row, "extras", None)
                and row.extras.get("logical_spec_label") == spec.label
            )
        ),
        "attempts": attempts,
    }
    write_json(run_root / "summary.json", summary)
    manifest = build_manifest(
        env,
        run_id=run_id,
        row_specs=row_specs,
        toolchain=toolchain,
        fixture_summary=fixture_summary,
        status="completed" if summary["rows_failed"] == 0 else "completed-with-failures",
    )
    write_json(run_root / "manifest.json", manifest)
    report = render_markdown_report(manifest, all_rows, summary)
    (run_root / "report.md").write_text(report, encoding="utf-8")
    write_json(run_root / "environment.json", _environment_snapshot(env))
    return all_rows, {"run_root": run_root, "manifest": manifest, "summary": summary, "report": report}


def _environment_snapshot(env: PortableEnvironment) -> dict[str, Any]:
    return {
        "THESIS_ROOT": str(env.thesis_root),
        "REPO_ROOT": str(env.repo_root),
        "PYTHON_BIN": str(env.python_bin),
        "NARGO_BIN": str(env.nargo_bin),
        "BB_BIN": str(env.bb_bin),
        "POSEIDON2_CMD": env.poseidon2_cmd,
        "HOME": str(env.home),
        "NARGO_HOME": str(env.nargo_home),
        "XDG_CACHE_HOME": str(env.xdg_cache_home),
        "CARGO_HOME": str(env.cargo_home),
        "CRS_PATH": str(env.crs_path),
        "EXPECTED_REPO_REVISION": env.expected_repo_revision,
        "EXPECTED_NARGO_VERSION": env.expected_nargo_version,
        "EXPECTED_BB_VERSION": env.expected_bb_version,
        "EXPECTED_POSEIDON2_DEPENDENCY_REVISION": env.expected_poseidon2_dependency_revision,
    }


def select_failed_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failed = []
    for row in rows:
        if row.get("status") != "ok" or not bool(row.get("verification_ok")):
            failed.append(row)
    return failed


def _logical_spec_label_from_result(row: dict[str, Any]) -> str | None:
    extras = row.get("extras")
    if isinstance(extras, dict) and extras.get("logical_spec_label"):
        return str(extras["logical_spec_label"])
    return None


def _metadata_result_rows(original_run_dir: Path) -> list[dict[str, Any]]:
    rows_by_identity: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    metadata_paths = list(original_run_dir.glob("rows/**/metadata.json"))
    metadata_paths.extend(original_run_dir.glob("resumes/*/rows/**/metadata.json"))
    for metadata_path in sorted(metadata_paths):
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        identity = (
            str(metadata.get("statement")),
            str(metadata.get("hash_name")),
            str(metadata.get("backend")),
            str(metadata.get("dataset_id")),
        )
        previous = rows_by_identity.get(identity)
        if previous is None or (
            metadata.get("status") == "verified"
            and previous.get("status") != "verified"
        ):
            rows_by_identity[identity] = metadata
    return list(rows_by_identity.values())


def build_resume_plan(
    env: PortableEnvironment,
    *,
    original_run_dir: Path,
    resume_id: str,
) -> dict[str, Any]:
    benchmark_json = original_run_dir / "benchmark.json"
    recovery_from_metadata = not benchmark_json.exists()
    rows = (
        json.loads(benchmark_json.read_text(encoding="utf-8"))
        if benchmark_json.exists()
        else _metadata_result_rows(original_run_dir)
    )
    failed_rows = select_failed_rows(rows)
    selected_specs = []
    full_specs = {spec.label: spec for spec in build_full_row_specs(env)}
    fallback_specs = {(spec.statement, spec.hash_name): spec for spec in full_specs.values()}
    selected_labels: set[str] = set()
    rows_by_label: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        label = _logical_spec_label_from_result(row)
        spec = full_specs.get(label) if label else fallback_specs.get(
            (row.get("statement"), row.get("hash_name"))
        )
        if spec is not None:
            rows_by_label.setdefault(spec.label, []).append(row)

    if recovery_from_metadata:
        for spec in full_specs.values():
            spec_rows = rows_by_label.get(spec.label, [])
            successful = [
                row
                for row in spec_rows
                if row.get("status") in {"ok", "verified"}
                and bool(row.get("verification_ok", True))
            ]
            if len(successful) == _expected_result_count(spec) and len(spec_rows) == len(successful):
                continue
            selected_specs.append(spec)
            selected_labels.add(spec.label)
    else:
        for row in failed_rows:
            label = _logical_spec_label_from_result(row)
            spec = full_specs.get(label) if label else fallback_specs.get(
                (row.get("statement"), row.get("hash_name"))
            )
            if spec is None or spec.label in selected_labels:
                continue
            selected_specs.append(spec)
            selected_labels.add(spec.label)
    return {
        "original_run_dir": str(original_run_dir),
        "resume_id": resume_id,
        "failed_rows": failed_rows,
        "existing_rows": rows,
        "recovery_from_metadata": recovery_from_metadata,
        "selected_specs": selected_specs,
    }


def run_resume(
    env: PortableEnvironment,
    *,
    original_run_dir: Path,
    resume_id: str | None = None,
) -> dict[str, Any]:
    if resume_id is None:
        resume_id = datetime.now(timezone.utc).strftime("resume_%Y%m%dT%H%M%SZ")
    plan = build_resume_plan(env, original_run_dir=original_run_dir, resume_id=resume_id)
    selected_specs: list[PortableRowSpec] = plan["selected_specs"]
    resume_root = original_run_dir / "resumes" / safe_filename(resume_id)
    resume_root.mkdir(parents=True, exist_ok=False)
    all_rows = []
    attempts = []
    for spec in selected_specs:
        row_root = resume_root / "rows" / safe_filename(spec.label)
        row_root.mkdir(parents=True, exist_ok=False)
        rows = _validate_and_annotate_rows(
            spec,
            _run_single_row(env, spec, run_id=resume_id, run_root=row_root),
        )
        all_rows.extend(rows)
        attempts.extend(_attempt_record(spec, row, run_dir=row_root) for row in rows)
    write_csv(resume_root / "benchmark.csv", all_rows)
    write_benchmark_json(resume_root / "benchmark.json", all_rows)
    merged = {
        "original_run_dir": str(original_run_dir),
        "resume_root": str(resume_root),
        "original_failed_rows": plan["failed_rows"],
        "resumed_rows": [row.to_dict() if hasattr(row, "to_dict") else row for row in all_rows],
        "attempts": attempts,
        "rows_resumed": len(all_rows),
        "logical_specs_resumed": len(selected_specs),
        "rows_failed": sum(1 for row in all_rows if row.status != "ok" or not row.verification_ok),
        "rows_ok": sum(1 for row in all_rows if row.status == "ok" and row.verification_ok),
    }
    write_json(resume_root / "merged_summary.json", merged)
    write_json(
        resume_root / "manifest.json",
        {
            "run_id": resume_id,
            "resume_of": str(original_run_dir),
            "selected_rows": [spec.label for spec in selected_specs],
            "environment": _environment_snapshot(env),
        },
    )
    if (
        plan.get("recovery_from_metadata")
        and selected_specs
        and all(row.status == "ok" and row.verification_ok for row in all_rows)
    ):
        _finalize_recovered_run(env, original_run_dir, plan, all_rows)
    return merged


def _metadata_to_record(
    metadata: dict[str, Any],
    spec: PortableRowSpec,
    *,
    repo_root: Path,
) -> BenchmarkRecord:
    payloads = load_proof_path(spec.input_path)
    dataset_id = str(metadata["dataset_id"])
    try:
        payload_index = int(dataset_id.rsplit("_", 1)[1])
    except (IndexError, ValueError):
        payload_index = 0
    payload = payloads[payload_index]
    artifact_paths = metadata.get("artifact_paths", {})
    timings = metadata.get("timings") or {}

    def artifact_size(name: str) -> int:
        value = artifact_paths.get(name)
        if not value:
            return 0
        path = Path(value)
        if not path.is_absolute():
            path = repo_root / path
        return path.stat().st_size if path.exists() else 0

    extras = {
        "logical_spec_label": spec.label,
        "payload_index": payload_index,
        "expected_payload_count": spec.expected_payload_count,
        "expected_result_count": _expected_result_count(spec),
        "physical_result_id": "::".join(
            [spec.statement, spec.hash_name, str(metadata["backend"]), dataset_id]
        ),
        "recovered_from_metadata": True,
        "metadata_path": str(metadata.get("artifact_paths", {}).get("timings", "")),
    }
    return BenchmarkRecord(
        dataset_id=dataset_id,
        statement=spec.statement,
        hash_name=spec.hash_name,
        backend=str(metadata["backend"]),
        address=payload.address,
        block_number=payload.block_number,
        proof_generation_time_s=float(timings.get("proof_generation_time_s", 0.0)),
        proof_verification_time_s=float(timings.get("proof_verification_time_s", 0.0)),
        witness_generation_time_s=float(timings.get("witness_generation_time_s", 0.0)),
        compile_time_s=float(timings.get("compile_time_s", 0.0)),
        proof_size_bytes=artifact_size("proof"),
        prove_peak_memory_bytes=int(timings.get("prove_peak_memory_bytes", 0)),
        verify_peak_memory_bytes=int(timings.get("verify_peak_memory_bytes", 0)),
        circuit_size_bytes=artifact_size("circuit_json") or None,
        constraint_count=None,
        account_proof_node_count=account_proof_node_count(payload),
        storage_proof_node_count=storage_proof_node_count(payload),
        raw_proof_byte_size=raw_proof_byte_size(payload),
        verification_ok=True,
        status="ok",
        extras=extras,
        proving_system=str(metadata.get("proving_system", "ultra_honk")),
    )


def _finalize_recovered_run(
    env: PortableEnvironment,
    original_run_dir: Path,
    plan: dict[str, Any],
    resumed_rows: list[BenchmarkRecord],
) -> None:
    output_names = (
        "benchmark.csv",
        "benchmark.json",
        "summary.json",
        "manifest.json",
        "report.md",
        "environment.json",
    )
    existing_outputs = [original_run_dir / name for name in output_names if (original_run_dir / name).exists()]
    if existing_outputs:
        raise FileExistsError(f"Refusing to overwrite recovered run outputs: {existing_outputs}")

    full_specs = build_full_row_specs(env)
    selected_labels = {spec.label for spec in plan["selected_specs"]}
    original_metadata = plan["existing_rows"]
    rows_by_label: dict[str, list[BenchmarkRecord]] = {}
    resumed_by_label: dict[str, list[BenchmarkRecord]] = {}
    for row in resumed_rows:
        label = row.extras["logical_spec_label"]
        resumed_by_label.setdefault(label, []).append(row)
    for spec in full_specs:
        if spec.label in selected_labels:
            rows_by_label[spec.label] = resumed_by_label[spec.label]
            continue
        metadata_rows = [
            metadata
            for metadata in original_metadata
            if metadata.get("statement") == spec.statement
            and metadata.get("hash_name") == spec.hash_name
            and metadata.get("status") == "verified"
        ]
        rows_by_label[spec.label] = [
            _metadata_to_record(metadata, spec, repo_root=env.repo_root)
            for metadata in metadata_rows
        ]

    all_rows: list[BenchmarkRecord] = []
    for spec in full_specs:
        spec_rows = _validate_and_annotate_rows(spec, rows_by_label[spec.label])
        all_rows.extend(spec_rows)

    toolchain = _validation_common(env)
    fixture_summary = validate_fixture_inventory(env, full_specs)
    attempts = []
    for spec in full_specs:
        attempts.extend(
            _attempt_record(spec, row, run_dir=original_run_dir / "rows" / safe_filename(spec.label))
            for row in rows_by_label[spec.label]
        )
    summary = {
        "run_id": original_run_dir.name,
        "logical_specs_total": len(full_specs),
        "logical_specs_ok": len(full_specs),
        "rows_total": len(all_rows),
        "rows_ok": len(all_rows),
        "rows_failed": 0,
        "attempts": attempts,
    }
    manifest = build_manifest(
        env,
        run_id=original_run_dir.name,
        row_specs=full_specs,
        toolchain=toolchain,
        fixture_summary=fixture_summary,
        status="completed",
    )
    write_csv(original_run_dir / "benchmark.csv", all_rows)
    write_benchmark_json(original_run_dir / "benchmark.json", all_rows)
    write_json(original_run_dir / "summary.json", summary)
    write_json(original_run_dir / "manifest.json", manifest)
    (original_run_dir / "report.md").write_text(
        render_markdown_report(manifest, all_rows, summary),
        encoding="utf-8",
    )
    write_json(original_run_dir / "environment.json", _environment_snapshot(env))


def render_markdown_report(manifest: dict[str, Any], rows: list[Any], summary: dict[str, Any]) -> str:
    lines = [
        "# UltraHONK Benchmark Run",
        "",
        f"- Run ID: `{manifest['run_id']}`",
        f"- Repository revision: `{manifest['repository_revision']}`",
        f"- Status: `{manifest['status']}`",
        f"- Logical specifications: `{summary.get('logical_specs_total', len(manifest['rows']))}`",
        f"- Physical result rows: `{summary['rows_total']}`",
        f"- Successful rows: `{summary['rows_ok']}`",
        f"- Failed rows: `{summary['rows_failed']}`",
        "",
        "## Rows",
    ]
    for row in rows:
        lines.append(
            f"- `{row.statement}` / `{row.hash_name}` / `{row.backend}`: `{row.status}` (verification_ok={row.verification_ok})"
        )
    lines.extend(
        [
            "",
            "## Environment",
            "",
            f"- Python: `{manifest['python']['path']}` ({manifest['python']['version']})",
            f"- Nargo: `{manifest['nargo']['path']}` ({manifest['nargo']['version']})",
            f"- BB: `{manifest['bb']['path']}` ({manifest['bb']['version']})",
            f"- Poseidon2 helper: `{manifest['poseidon2']['command']}`",
            "",
            manifest["hardware_variable_note"],
        ]
    )
    return "\n".join(lines) + "\n"


def _print_human_preflight(report: dict[str, Any]) -> None:
    print("Portable UltraHONK preflight passed.")
    print(f"Repository revision: {report['repository_revision']}")
    print(f"Python: {report['python']['version']} ({report['python']['path']})")
    print(f"Nargo: {report['nargo']['version']} ({report['nargo']['path']})")
    print(f"BB: {report['bb']['version']} ({report['bb']['path']})")
    print(f"Rows: {len(report['rows'])}")
    print(f"CRS files: {len(report['crs'])}")


def cmd_preflight(args: argparse.Namespace) -> int:
    env = derive_environment()
    rows = build_full_row_specs(env) if args.matrix == "full" else build_smoke_row_specs(env)
    report = perform_preflight(env, rows)
    _print_human_preflight(report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def cmd_run_full(args: argparse.Namespace) -> int:
    env = derive_environment()
    run_id = args.run_id or datetime.now(timezone.utc).strftime("ultrahonk_%Y%m%dT%H%M%SZ")
    row_specs = build_full_row_specs(env)
    report = perform_preflight(env, row_specs)
    print(json.dumps({"preflight": report}, indent=2, sort_keys=True))
    if args.repeat < 1:
        raise ValueError("--repeat must be >= 1")
    final_root = None
    any_failed = False
    for index in range(1, args.repeat + 1):
        attempt_run_id = run_id if args.repeat == 1 else f"{run_id}_r{index:02d}"
        rows, info = run_matrix(env, run_id=attempt_run_id, row_specs=row_specs)
        final_root = info["run_root"]
        any_failed = any_failed or info["summary"]["rows_failed"] > 0
        print(f"Run {index}: {info['run_root']}")
    if final_root is None:
        raise RuntimeError("No runs were executed.")
    print(f"Final output directory: {final_root}")
    print(f"Manifest: {final_root / 'manifest.json'}")
    print(f"Benchmark CSV: {final_root / 'benchmark.csv'}")
    print(f"Benchmark JSON: {final_root / 'benchmark.json'}")
    print(f"Summary JSON: {final_root / 'summary.json'}")
    print(f"Report: {final_root / 'report.md'}")
    return 1 if any_failed else 0


def cmd_run_smoke(args: argparse.Namespace) -> int:
    env = derive_environment()
    row_specs = build_smoke_row_specs(env)
    report = perform_preflight(env, row_specs)
    print(json.dumps({"preflight": report}, indent=2, sort_keys=True))
    run_id = args.run_id or datetime.now(timezone.utc).strftime("ultrahonk_smoke_%Y%m%dT%H%M%SZ")
    rows, info = run_matrix(env, run_id=run_id, row_specs=row_specs)
    print(f"Final output directory: {info['run_root']}")
    print(f"Manifest: {info['run_root'] / 'manifest.json'}")
    print(f"Benchmark CSV: {info['run_root'] / 'benchmark.csv'}")
    print(f"Benchmark JSON: {info['run_root'] / 'benchmark.json'}")
    print(f"Summary JSON: {info['run_root'] / 'summary.json'}")
    print(f"Report: {info['run_root'] / 'report.md'}")
    return 1 if info["summary"]["rows_failed"] > 0 else 0


def cmd_resume(args: argparse.Namespace) -> int:
    env = derive_environment()
    original_run_dir = Path(args.run_dir)
    if not original_run_dir.exists():
        raise FileNotFoundError(f"Existing run directory not found: {original_run_dir}")
    merged = run_resume(env, original_run_dir=original_run_dir, resume_id=args.resume_id)
    print(f"Resume directory: {merged['resume_root']}")
    print(f"Merged summary: {Path(merged['resume_root']) / 'merged_summary.json'}")
    print(f"Resume benchmark JSON: {Path(merged['resume_root']) / 'benchmark.json'}")
    return 1 if merged["rows_failed"] > 0 else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Portable UltraHONK benchmark bundle.")
    sub = parser.add_subparsers(dest="command", required=True)

    preflight = sub.add_parser("preflight", help="Validate the portable UltraHONK environment.")
    preflight.add_argument(
        "--matrix",
        choices=["full", "smoke"],
        default="full",
        help="Validate the full 14-row matrix or the 4-row smoke matrix.",
    )
    preflight.set_defaults(func=cmd_preflight)

    run_full = sub.add_parser("run-full", help="Run the full 14-row UltraHONK pass.")
    run_full.add_argument("--run-id", default="", help="Optional run ID. Defaults to a timestamped ID.")
    run_full.add_argument("--repeat", type=int, default=1, help="Repeat the full run N times.")
    run_full.set_defaults(func=cmd_run_full)

    smoke = sub.add_parser("run-smoke", help="Run the 4-row smoke matrix.")
    smoke.add_argument("--run-id", default="", help="Optional run ID. Defaults to a timestamped ID.")
    smoke.set_defaults(func=cmd_run_smoke)

    resume = sub.add_parser("resume", help="Resume failed rows from an existing run directory.")
    resume.add_argument("run_dir", help="Existing run directory containing benchmark.json.")
    resume.add_argument("--resume-id", default="", help="Optional resume attempt label.")
    resume.set_defaults(func=cmd_resume)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
