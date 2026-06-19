from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class DatasetPayloadRecord:
    dataset_id: str
    source_file: str
    source_index: int
    address: str
    block_number: int | None


@dataclass(slots=True)
class DatasetFileRecord:
    path: str
    payload_count: int
    dataset_ids: list[str]
    addresses: list[str]
    block_numbers: list[int]
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DatasetDiscoveryReport:
    root: str
    missing_dataset: bool
    files: list[DatasetFileRecord]
    payloads: list[DatasetPayloadRecord]
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MetadataValidationResult:
    dataset_id: str
    source_file: str
    source_index: int
    ok: bool
    bounded_ok: bool
    bounded_error: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HashEnvironmentStatus:
    hash_name: str
    configured: bool
    command_template_present: bool
    vectors_env_path: str | None
    vectors_loaded: bool
    vector_count: int
    error: str | None = None


@dataclass(slots=True)
class HashValidationResult:
    dataset_id: str
    source_file: str
    source_index: int
    hash_name: str
    adapter_configured: bool
    baseline_ok: bool | None
    state_root: str | None = None
    account_proof_node_count: int | None = None
    storage_proof_node_count: int | None = None
    raw_proof_byte_size: int | None = None
    error: str | None = None


@dataclass(slots=True)
class ConsistencyFinding:
    level: str
    code: str
    message: str
    dataset_id: str | None = None
    reference: str | None = None


@dataclass(slots=True)
class ManifestSummary:
    total_files: int
    total_payloads: int
    discovery_errors: int
    metadata_ok: int
    metadata_errors: int
    hash_ok: int
    hash_errors: int
    consistency_errors: int
    consistency_warnings: int
    has_errors: bool


@dataclass(slots=True)
class DatasetManifest:
    generated_at: str
    variant: str
    root: str
    reference_root: str | None
    discovery: DatasetDiscoveryReport
    hash_environment: HashEnvironmentStatus
    metadata_validation: list[MetadataValidationResult]
    hash_validation: list[HashValidationResult]
    consistency_findings: list[ConsistencyFinding]
    summary: ManifestSummary

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
