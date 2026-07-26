from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from thesis_c.benchmark import portable_bundle as bundle


def _env(thesis_root: Path, **overrides: str) -> dict[str, str]:
    env = {
        "THESIS_ROOT": str(thesis_root),
        "PYTHON_BIN": str(Path("/usr/bin/python3")),
        "NARGO_BIN": str(Path("/usr/bin/nargo")),
        "BB_BIN": str(Path("/usr/bin/bb")),
        "POSEIDON2_CMD": str(Path("/usr/bin/poseidon2")) + " {hex0x}",
        "HOME": str(thesis_root),
        "NARGO_HOME": str(thesis_root / "nargo"),
        "XDG_CACHE_HOME": str(thesis_root / ".cache"),
        "CARGO_HOME": str(thesis_root / ".cargo"),
        "CRS_PATH": str(thesis_root / ".bb-crs"),
        "EXPECTED_REPO_REVISION": bundle.EXPECTED_REPO_REVISION,
        "EXPECTED_NARGO_VERSION": bundle.EXPECTED_NARGO_VERSION,
        "EXPECTED_BB_VERSION": bundle.EXPECTED_BB_VERSION,
        "EXPECTED_POSEIDON2_DEPENDENCY_REVISION": bundle.EXPECTED_POSEIDON2_DEPENDENCY_REVISION,
    }
    env.update(overrides)
    return env


def test_derive_environment_requires_thesis_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("THESIS_ROOT", raising=False)
    with pytest.raises(ValueError, match="THESIS_ROOT"):
        bundle.derive_environment({})


def test_missing_poseidon2_helper_default_raises(tmp_path: Path) -> None:
    thesis_root = tmp_path / "Thesis"
    thesis_root.mkdir()

    with pytest.raises(FileNotFoundError, match="POSEIDON2_CMD"):
        bundle._resolve_poseidon2_cmd({}, thesis_root)


def test_full_row_inventory_is_exact_and_excludes_anchored_eoa(tmp_path: Path) -> None:
    thesis_root = tmp_path / "Thesis"
    repo_root = thesis_root / "SNARK" / "thesis_c"
    for path in [
        repo_root / "datasets" / "poseidon2",
        repo_root / "datasets" / "keccak",
        repo_root / "datasets" / "eoa_activity",
        thesis_root / "sample_proofs",
    ]:
        path.mkdir(parents=True, exist_ok=True)

    env = bundle.PortableEnvironment(
        thesis_root=thesis_root,
        repo_root=repo_root,
        python_bin=Path("/usr/bin/python3"),
        nargo_bin=Path("/usr/bin/nargo"),
        bb_bin=Path("/usr/bin/bb"),
        poseidon2_cmd="/usr/bin/poseidon2 {hex0x}",
        home=thesis_root,
        nargo_home=thesis_root / "nargo",
        xdg_cache_home=thesis_root / ".cache",
        cargo_home=thesis_root / ".cargo",
        crs_path=thesis_root / ".bb-crs",
    )

    specs = bundle.build_full_row_specs(env)
    labels = [spec.label for spec in specs]

    assert len(specs) == 14
    assert len(set(labels)) == 14
    assert "eoa_activity_anchored" not in labels
    assert "eoa_activity_anchored_poseidon2" not in labels
    assert [spec.expected_payload_count for spec in specs[-2:]] == [2, 2]
    assert [spec.expected_result_count for spec in specs[-2:]] == [1, 1]
    assert labels == [
        "account_inclusion_keccak_supplied_root",
        "account_inclusion_poseidon2_supplied_root",
        "account_inclusion_keccak_anchored",
        "account_inclusion_poseidon2_anchored",
        "balance_keccak_supplied_root",
        "balance_poseidon2_supplied_root",
        "balance_keccak_anchored",
        "balance_poseidon2_anchored",
        "codehash_keccak_supplied_root",
        "codehash_poseidon2_supplied_root",
        "codehash_keccak_anchored",
        "codehash_poseidon2_anchored",
        "eoa_activity_keccak_supplied_root",
        "eoa_activity_poseidon2_supplied_root",
    ]
    assert bundle.build_smoke_row_specs(env) == [
        specs[0],
        specs[1],
        specs[2],
        specs[7],
    ]


def test_portable_environment_preserves_caller_run_id() -> None:
    env_text = Path("benchmarks/portable/benchmark_env.local.sh").read_text(encoding="utf-8")
    assert 'export RUN_ID="${RUN_ID:-}"' in env_text
    assert 'export RUN_ID=""' not in env_text


def test_fixture_inventory_uses_real_fixture_paths() -> None:
    thesis_root = Path("/Users/doodleaks/Developer/Thesis")
    repo_root = thesis_root / "SNARK" / "thesis_c"
    env = bundle.PortableEnvironment(
        thesis_root=thesis_root,
        repo_root=repo_root,
        python_bin=Path("/Users/doodleaks/Developer/Thesis/.venv/bin/python"),
        nargo_bin=Path("/Users/doodleaks/.nargo/bin/nargo"),
        bb_bin=Path("/Users/doodleaks/.bb/bb"),
        poseidon2_cmd="/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}",
        home=thesis_root,
        nargo_home=thesis_root / "nargo",
        xdg_cache_home=thesis_root / ".cache",
        cargo_home=thesis_root / ".cargo",
        crs_path=thesis_root / ".bb-crs",
    )
    specs = bundle.build_full_row_specs(env)
    summary = bundle.validate_fixture_inventory(env, specs)

    assert len(summary["fixtures"]) == 14
    assert summary["fixtures"][0]["path"].endswith("sample_proofs/proof_keccak_forest.json")
    assert any(item["anchored"] for item in summary["fixtures"])


def test_human_preflight_reads_versions_from_manifest_schema(capsys: pytest.CaptureFixture[str]) -> None:
    report = {
        "repository_revision": bundle.EXPECTED_REPO_REVISION,
        "python": {"path": "/venv/bin/python", "version": "3.14.0"},
        "nargo": {"path": "/nargo", "version": bundle.EXPECTED_NARGO_VERSION},
        "bb": {"path": "/bb", "version": bundle.EXPECTED_BB_VERSION},
        "rows": [{"label": "row"}],
        "crs": [{"path": "/crs/g1.dat"}],
    }

    bundle._print_human_preflight(report)

    output = capsys.readouterr().out
    assert "Portable UltraHONK preflight passed." in output
    assert "Python: 3.14.0 (/venv/bin/python)" in output
    assert f"Nargo: {bundle.EXPECTED_NARGO_VERSION} (/nargo)" in output
    assert f"BB: {bundle.EXPECTED_BB_VERSION} (/bb)" in output


class _PortableResult:
    def __init__(self, dataset_id: str) -> None:
        self.dataset_id = dataset_id
        self.statement = "eoa_activity"
        self.hash_name = "poseidon2"
        self.backend = "ultra_honk"
        self.status = "ok"
        self.verification_ok = True
        self.error = None


def _spec(expected_payload_count: int) -> bundle.PortableRowSpec:
    return bundle.PortableRowSpec(
        label="eoa_activity_poseidon2_supplied_root",
        statement="eoa_activity",
        hash_name="poseidon2",
        input_path=Path("input.json"),
        expected_payload_count=expected_payload_count,
    )


def test_result_count_matches_one_payload_spec() -> None:
    rows = bundle._validate_and_annotate_rows(
        bundle.PortableRowSpec(
            label="account_inclusion_keccak_supplied_root",
            statement="account_inclusion",
            hash_name="keccak256",
            input_path=Path("input.json"),
        ),
        [_PortableResult("payload-0")],
    )
    assert len(rows) == 1


def test_result_count_matches_two_payload_spec_and_ids_are_unique() -> None:
    rows = bundle._validate_and_annotate_rows(
        _spec(2),
        [_PortableResult("payload-0"), _PortableResult("payload-1")],
    )
    assert [_row.dataset_id for _row in rows] == ["payload-0", "payload-1"]
    assert len({bundle._physical_result_id(row) for row in rows}) == 2


@pytest.mark.parametrize(
    ("returned", "message"),
    [(1, "Expected 2 result row"), (3, "Expected 2 result row")],
)
def test_result_count_mismatch_is_strict(returned: int, message: str) -> None:
    with pytest.raises(RuntimeError, match=message):
        bundle._validate_and_annotate_rows(
            _spec(2),
            [_PortableResult(f"payload-{index}") for index in range(returned)],
        )


def test_duplicate_physical_result_identity_is_rejected() -> None:
    with pytest.raises(RuntimeError, match="Duplicate physical result identity"):
        bundle._validate_and_annotate_rows(
            _spec(2),
            [_PortableResult("payload-0"), _PortableResult("payload-0")],
        )


def test_manifest_and_report_distinguish_logical_and_physical_counts() -> None:
    manifest = {
        "run_id": "run-1",
        "repository_revision": bundle.EXPECTED_REPO_REVISION,
        "status": "completed",
        "rows": [{"label": "one"}, {"label": "two"}],
        "python": {"path": "/python", "version": "3.14"},
        "nargo": {"path": "/nargo", "version": "nargo"},
        "bb": {"path": "/bb", "version": "bb"},
        "poseidon2": {"command": "poseidon2"},
        "hardware_variable_note": "note",
    }
    summary = {
        "logical_specs_total": 2,
        "rows_total": 3,
        "rows_ok": 3,
        "rows_failed": 0,
    }
    report = bundle.render_markdown_report(
        manifest,
        [_PortableResult("payload-0")],
        summary,
    )
    assert "Logical specifications: `2`" in report
    assert "Physical result rows: `3`" in report


def test_resume_groups_multi_payload_failures_without_duplicate_specs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    thesis_root = tmp_path / "Thesis"
    repo_root = thesis_root / "SNARK" / "thesis_c"
    original_run_dir = repo_root / "benchmarks" / "runs" / "run-1"
    original_run_dir.mkdir(parents=True)
    (original_run_dir / "benchmark.json").write_text(
        json.dumps(
            [
                {
                    "statement": "eoa_activity",
                    "hash_name": "poseidon2",
                    "status": "ok",
                    "verification_ok": True,
                    "extras": {
                        "logical_spec_label": "eoa_activity_poseidon2_supplied_root",
                        "payload_index": 0,
                    },
                },
                {
                    "statement": "eoa_activity",
                    "hash_name": "poseidon2",
                    "status": "failed",
                    "verification_ok": False,
                    "extras": {
                        "logical_spec_label": "eoa_activity_poseidon2_supplied_root",
                        "payload_index": 1,
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    env = bundle.PortableEnvironment(
        thesis_root=thesis_root,
        repo_root=repo_root,
        python_bin=Path("/usr/bin/python3"),
        nargo_bin=Path("/usr/bin/nargo"),
        bb_bin=Path("/usr/bin/bb"),
        poseidon2_cmd="/usr/bin/poseidon2 {hex0x}",
        home=thesis_root,
        nargo_home=thesis_root / "nargo",
        xdg_cache_home=thesis_root / ".cache",
        cargo_home=thesis_root / ".cargo",
        crs_path=thesis_root / ".bb-crs",
    )
    monkeypatch.setattr(bundle, "build_full_row_specs", lambda env: [_spec(2)])

    plan = bundle.build_resume_plan(
        env,
        original_run_dir=original_run_dir,
        resume_id="resume-1",
    )
    assert [spec.label for spec in plan["selected_specs"]] == [
        "eoa_activity_poseidon2_supplied_root"
    ]

    (original_run_dir / "benchmark.json").write_text(
        json.dumps(
            [
                {
                    "statement": "eoa_activity",
                    "hash_name": "poseidon2",
                    "status": "ok",
                    "verification_ok": True,
                    "extras": {
                        "logical_spec_label": "eoa_activity_poseidon2_supplied_root",
                        "payload_index": 0,
                    },
                },
                {
                    "statement": "eoa_activity",
                    "hash_name": "poseidon2",
                    "status": "ok",
                    "verification_ok": True,
                    "extras": {
                        "logical_spec_label": "eoa_activity_poseidon2_supplied_root",
                        "payload_index": 1,
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    complete_plan = bundle.build_resume_plan(
        env,
        original_run_dir=original_run_dir,
        resume_id="resume-2",
    )
    assert complete_plan["selected_specs"] == []


def test_version_mismatch_fails_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    thesis_root = tmp_path / "Thesis"
    repo_root = thesis_root / "SNARK" / "thesis_c"
    poseidon2_root = tmp_path / "besu_bonsai"
    repo_root.mkdir(parents=True)
    env = bundle.PortableEnvironment(
        thesis_root=thesis_root,
        repo_root=repo_root,
        python_bin=Path("/usr/bin/python3"),
        nargo_bin=Path("/usr/bin/nargo"),
        bb_bin=Path("/usr/bin/bb"),
        poseidon2_cmd="/usr/bin/poseidon2 {hex0x}",
        home=thesis_root,
        nargo_home=thesis_root / "nargo",
        xdg_cache_home=thesis_root / ".cache",
        cargo_home=thesis_root / ".cargo",
        crs_path=thesis_root / ".bb-crs",
    )

    monkeypatch.setattr(bundle, "_tool_version", lambda path, args=None: "0.0.0" if path == env.nargo_bin else bundle.EXPECTED_BB_VERSION)
    monkeypatch.setattr(bundle, "_poseidon2_dependency_root", lambda env: poseidon2_root)
    monkeypatch.setattr(
        bundle,
        "_git_sha",
        lambda path, *args: bundle.EXPECTED_POSEIDON2_DEPENDENCY_REVISION
        if path == poseidon2_root
        else bundle.EXPECTED_REPO_REVISION,
    )
    monkeypatch.setattr(bundle, "_git_dirty_info", lambda repo_root: {"dirty": False, "status_porcelain": [], "diff_sha256": "0" * 64, "diff_line_count": 0})
    monkeypatch.setattr(bundle, "_system_metadata", lambda: {"cpu": "cpu", "physical_memory_bytes": 1, "os_version": "macOS"})
    monkeypatch.setattr(bundle, "_require_imports", lambda: {})
    monkeypatch.setattr(bundle, "_sha256_file", lambda path: "sha256")
    monkeypatch.setattr(bundle, "validate_fixture_inventory", lambda env, row_specs: {"fixtures": []})

    with pytest.raises(RuntimeError, match="Nargo version mismatch"):
        bundle._validation_common(env)


def test_deterministic_run_paths_and_resume_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    thesis_root = tmp_path / "Thesis"
    repo_root = thesis_root / "SNARK" / "thesis_c"
    run_root = repo_root / "benchmarks" / "runs" / "portable_run"
    repo_root.mkdir(parents=True)
    env = bundle.PortableEnvironment(
        thesis_root=thesis_root,
        repo_root=repo_root,
        python_bin=Path("/usr/bin/python3"),
        nargo_bin=Path("/usr/bin/nargo"),
        bb_bin=Path("/usr/bin/bb"),
        poseidon2_cmd="/usr/bin/poseidon2 {hex0x}",
        home=thesis_root,
        nargo_home=thesis_root / "nargo",
        xdg_cache_home=thesis_root / ".cache",
        cargo_home=thesis_root / ".cargo",
        crs_path=thesis_root / ".bb-crs",
    )

    monkeypatch.setattr(bundle, "_validation_common", lambda env: {"repository_revision": bundle.EXPECTED_REPO_REVISION, "dirty_worktree": {"dirty": False}, "dirty_worktree_diff_sha256": "0" * 64, "dirty_worktree_diff_line_count": 0, "dirty_worktree_status": [], "python_version": "3.14", "nargo_version": bundle.EXPECTED_NARGO_VERSION, "nargo_sha256": "n", "bb_version": bundle.EXPECTED_BB_VERSION, "bb_sha256": "b", "poseidon2_executable": "/usr/bin/poseidon2", "poseidon2_sha256": "p", "poseidon2_dependency_revision": bundle.EXPECTED_POSEIDON2_DEPENDENCY_REVISION, "crs": [], "cpu": "cpu", "physical_memory_bytes": 1, "free_disk_bytes": 1, "disk_path": str(repo_root), "os_version": "macOS"})
    monkeypatch.setattr(bundle, "validate_fixture_inventory", lambda env, row_specs: {"fixtures": []})
    monkeypatch.setattr(
        bundle,
        "resolve_circuit_package",
        lambda statement, hash_name, repo_root: SimpleNamespace(
            nargo_package_name=f"{statement}_{hash_name}",
            package_dir=repo_root / "dummy_package",
            expected_circuit_json=repo_root / "target" / f"{statement}_{hash_name}.json",
        ),
    )

    class DummyRow:
        def __init__(self, statement: str, hash_name: str) -> None:
            self.statement = statement
            self.hash_name = hash_name
            self.backend = "ultra_honk"
            self.status = "ok"
            self.verification_ok = True
            self.error = None

        def to_dict(self) -> dict[str, object]:
            return {
                "statement": self.statement,
                "hash_name": self.hash_name,
                "backend": self.backend,
                "status": self.status,
                "verification_ok": self.verification_ok,
            }

    def fake_run_single_row(env, spec, *, run_id, run_root):
        (run_root / "ok.txt").write_text(spec.label, encoding="utf-8")
        return [DummyRow(spec.statement, spec.hash_name)]

    monkeypatch.setattr(bundle, "_run_single_row", fake_run_single_row)

    rows, info = bundle.run_matrix(env, run_id="portable run", row_specs=bundle.build_smoke_row_specs(env))
    assert info["run_root"] == repo_root / "benchmarks" / "runs" / "portable_run"
    assert (info["run_root"] / "rows" / "account_inclusion_keccak_supplied_root" / "ok.txt").exists()
    assert len(rows) == 4

    benchmark_json = info["run_root"] / "benchmark.json"
    benchmark_json.write_text(
        json.dumps(
            [
                {"statement": "account_inclusion", "hash_name": "keccak256", "status": "ok", "verification_ok": True},
                {"statement": "balance_verification", "hash_name": "poseidon2", "status": "error", "verification_ok": False},
            ]
        ),
        encoding="utf-8",
    )
    plan = bundle.build_resume_plan(env, original_run_dir=info["run_root"], resume_id="resume-1")
    assert [spec.label for spec in plan["selected_specs"]] == ["balance_poseidon2_supplied_root"]
    assert len(plan["failed_rows"]) == 1


def test_resume_selection_reruns_only_failed_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    thesis_root = tmp_path / "Thesis"
    repo_root = thesis_root / "SNARK" / "thesis_c"
    original_run_dir = repo_root / "benchmarks" / "runs" / "run_1"
    original_run_dir.mkdir(parents=True)
    (original_run_dir / "benchmark.json").write_text(
        json.dumps(
            [
                {"statement": "account_inclusion", "hash_name": "keccak256", "status": "ok", "verification_ok": True},
                {"statement": "codehash_verification_anchored_poseidon2", "hash_name": "poseidon2", "status": "error", "verification_ok": False},
            ]
        ),
        encoding="utf-8",
    )

    env = bundle.PortableEnvironment(
        thesis_root=thesis_root,
        repo_root=repo_root,
        python_bin=Path("/usr/bin/python3"),
        nargo_bin=Path("/usr/bin/nargo"),
        bb_bin=Path("/usr/bin/bb"),
        poseidon2_cmd="/usr/bin/poseidon2 {hex0x}",
        home=thesis_root,
        nargo_home=thesis_root / "nargo",
        xdg_cache_home=thesis_root / ".cache",
        cargo_home=thesis_root / ".cargo",
        crs_path=thesis_root / ".bb-crs",
    )

    monkeypatch.setattr(bundle, "_validation_common", lambda env: {"repository_revision": bundle.EXPECTED_REPO_REVISION, "dirty_worktree": {"dirty": False}, "dirty_worktree_diff_sha256": "0" * 64, "dirty_worktree_diff_line_count": 0, "dirty_worktree_status": [], "python_version": "3.14", "nargo_version": bundle.EXPECTED_NARGO_VERSION, "nargo_sha256": "n", "bb_version": bundle.EXPECTED_BB_VERSION, "bb_sha256": "b", "poseidon2_executable": "/usr/bin/poseidon2", "poseidon2_sha256": "p", "poseidon2_dependency_revision": bundle.EXPECTED_POSEIDON2_DEPENDENCY_REVISION, "crs": [], "cpu": "cpu", "physical_memory_bytes": 1, "free_disk_bytes": 1, "disk_path": str(repo_root), "os_version": "macOS"})
    monkeypatch.setattr(bundle, "validate_fixture_inventory", lambda env, row_specs: {"fixtures": []})

    selected: list[str] = []

    class DummyRow:
        def __init__(self, label: str) -> None:
            self.statement = label
            self.hash_name = "poseidon2"
            self.backend = "ultra_honk"
            self.status = "ok"
            self.verification_ok = True
            self.error = None

        def to_dict(self) -> dict[str, object]:
            return {
                "statement": self.statement,
                "hash_name": self.hash_name,
                "status": self.status,
                "verification_ok": self.verification_ok,
            }

    def fake_run_single_row(env, spec, *, run_id, run_root):
        selected.append(spec.label)
        return [DummyRow(spec.label)]

    monkeypatch.setattr(bundle, "_run_single_row", fake_run_single_row)

    merged = bundle.run_resume(env, original_run_dir=original_run_dir, resume_id="resume_1")

    assert selected == ["codehash_poseidon2_anchored"]
    assert merged["rows_resumed"] == 1
    assert merged["rows_failed"] == 0
