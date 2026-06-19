from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from thesis_c.datasets.schema import (
    DatasetDiscoveryReport,
    DatasetFileRecord,
    DatasetPayloadRecord,
)
from thesis_c.proof_inputs.loaders import load_proof_file
from thesis_c.proof_inputs.schema import ProofPayload


@dataclass(slots=True)
class DiscoveredPayload:
    record: DatasetPayloadRecord
    payload: ProofPayload


@dataclass(slots=True)
class DiscoveryContext:
    report: DatasetDiscoveryReport
    payloads: list[DiscoveredPayload]


def dataset_id_for_payload(payload: ProofPayload) -> str:
    source_file = Path(payload.source_file or "memory")
    source_index = payload.source_index if payload.source_index is not None else 0
    return f"{source_file.stem}_{source_index}"


def _file_path_for_report(root: Path, file_path: Path) -> str:
    if root.is_dir():
        try:
            return file_path.relative_to(root).as_posix()
        except ValueError:
            return file_path.as_posix()
    return file_path.name


def _payload_record(payload: ProofPayload) -> DatasetPayloadRecord:
    source_file = payload.source_file or "memory"
    source_index = payload.source_index if payload.source_index is not None else 0
    return DatasetPayloadRecord(
        dataset_id=dataset_id_for_payload(payload),
        source_file=str(Path(source_file).as_posix()),
        source_index=source_index,
        address=payload.address,
        block_number=payload.block_number,
    )


def _sorted_payload_records(
    payloads: list[DatasetPayloadRecord],
) -> list[DatasetPayloadRecord]:
    return sorted(
        payloads,
        key=lambda item: (item.source_file, item.source_index, item.dataset_id),
    )


def discover_dataset(path: str | Path) -> DiscoveryContext:
    target = Path(path)
    if target.is_file():
        file_paths = [target]
    elif target.is_dir():
        file_paths = sorted(target.rglob("*.json"))
    else:
        raise FileNotFoundError(f"Path does not exist: {target}")

    file_records: list[DatasetFileRecord] = []
    dataset_errors: list[str] = []
    discovered_payloads: list[DiscoveredPayload] = []
    payload_records: list[DatasetPayloadRecord] = []

    for file_path in file_paths:
        file_label = _file_path_for_report(target, file_path)
        try:
            payloads = load_proof_file(file_path)
        except Exception as exc:
            message = str(exc)
            dataset_errors.append(f"{file_label}: {message}")
            file_records.append(
                DatasetFileRecord(
                    path=file_label,
                    payload_count=0,
                    dataset_ids=[],
                    addresses=[],
                    block_numbers=[],
                    errors=[message],
                )
            )
            continue

        records_for_file: list[DatasetPayloadRecord] = []
        for payload in payloads:
            record = _payload_record(payload)
            records_for_file.append(record)
            payload_records.append(record)
            discovered_payloads.append(DiscoveredPayload(record=record, payload=payload))

        block_numbers = sorted(
            {
                item.block_number
                for item in records_for_file
                if item.block_number is not None
            }
        )
        addresses = sorted({item.address.lower() for item in records_for_file})
        dataset_ids = [item.dataset_id for item in records_for_file]

        file_records.append(
            DatasetFileRecord(
                path=file_label,
                payload_count=len(records_for_file),
                dataset_ids=dataset_ids,
                addresses=addresses,
                block_numbers=block_numbers,
                errors=[],
            )
        )

    file_records = sorted(file_records, key=lambda item: item.path)
    payload_records = _sorted_payload_records(payload_records)

    report = DatasetDiscoveryReport(
        root=target.resolve().as_posix(),
        missing_dataset=target.is_dir() and len(file_paths) == 0,
        files=file_records,
        payloads=payload_records,
        errors=sorted(dataset_errors),
    )
    return DiscoveryContext(report=report, payloads=discovered_payloads)
