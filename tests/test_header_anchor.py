from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import subprocess
import os

import pytest
import tomllib

from thesis_c.proof_inputs.header_anchor import (
    build_header_anchor_witness,
    MAX_HEADER_BYTES,
    EXPECTED_HEADER_FIELD_COUNT,
    header_uniformity_report,
    load_default_header_anchor_fixtures,
    validate_header_fixture,
    write_header_anchor_prover_toml,
)
from thesis_c.noir.witness_writer import write_prover_toml


ROOT = Path(__file__).resolve().parents[1]
REAL_HOODI_HEADER_DATA = Path("/Users/doodleaks/Developer/Thesis/hoodi_blocks_10.rlp")
HEADER_PACKAGE = ROOT / "circuits_header_anchor"
HEADER_PACKAGE_PROVER = HEADER_PACKAGE / "Prover.toml"


def _parse_rlp_item(data: bytes, offset: int) -> tuple[int, bool, int, int]:
    first = data[offset]
    if first <= 0x7F:
        return offset + 1, False, 1, 1
    if first <= 0xB7:
        payload_len = first - 0x80
        return offset + 1 + payload_len, False, 1 + payload_len, payload_len
    if first <= 0xBF:
        len_of_len = first - 0xB7
        payload_len = int.from_bytes(data[offset + 1 : offset + 1 + len_of_len], "big")
        return offset + 1 + len_of_len + payload_len, False, 1 + len_of_len + payload_len, payload_len
    if first <= 0xF7:
        payload_len = first - 0xC0
        return offset + 1 + payload_len, True, 1 + payload_len, payload_len
    len_of_len = first - 0xF7
    payload_len = int.from_bytes(data[offset + 1 : offset + 1 + len_of_len], "big")
    return offset + 1 + len_of_len + payload_len, True, 1 + len_of_len + payload_len, payload_len


def _parse_real_hoodi_headers() -> list[dict[str, object]]:
    data = REAL_HOODI_HEADER_DATA.read_bytes()
    records = []
    offset = 0
    while offset < len(data):
        record_end, record_is_list, record_enc_len, record_payload_len = _parse_rlp_item(data, offset)
        assert record_is_list
        record_payload_offset = offset + (record_enc_len - record_payload_len)
        header_end, header_is_list, header_enc_len, header_payload_len = _parse_rlp_item(
            data, record_payload_offset
        )
        assert header_is_list
        header_bytes = data[record_payload_offset:header_end]

        header_payload_offset = record_payload_offset + (header_enc_len - header_payload_len)
        field_offsets = []
        field_offset = header_payload_offset
        while field_offset < header_end:
            field_end, field_is_list, field_enc_len, field_payload_len = _parse_rlp_item(data, field_offset)
            field_offsets.append((field_offset, field_end, field_is_list, field_enc_len, field_payload_len))
            field_offset = field_end

        assert len(field_offsets) == EXPECTED_HEADER_FIELD_COUNT
        assert field_offset == header_end
        state_root_start = field_offsets[3][0] + (field_offsets[3][3] - field_offsets[3][4])
        state_root = data[state_root_start : field_offsets[3][1]]
        block_number_start = field_offsets[8][0] + (field_offsets[8][3] - field_offsets[8][4])
        block_number_bytes = data[block_number_start : field_offsets[8][1]]
        block_number = int.from_bytes(block_number_bytes, "big") if block_number_bytes else 0
        records.append(
            {
                "record_len": record_enc_len,
                "header_len": header_enc_len,
                "field_count": len(field_offsets),
                "block_number": block_number,
                "state_root": state_root,
                "header_bytes": header_bytes,
            }
        )
        offset = record_end
    return records


def _run_header_execute(noir_inputs: dict[str, object], witness_name: str) -> subprocess.CompletedProcess[str]:
    original = HEADER_PACKAGE_PROVER.read_text(encoding="utf-8") if HEADER_PACKAGE_PROVER.exists() else None
    env = dict(os.environ)
    env["HOME"] = str(ROOT.parents[1])
    env["XDG_CACHE_HOME"] = str(ROOT.parents[1] / ".cache")
    env["NARGO_HOME"] = str(ROOT.parents[1] / "nargo")
    try:
        write_prover_toml(HEADER_PACKAGE_PROVER, noir_inputs)
        return subprocess.run(
            [
                "nargo",
                "execute",
                witness_name,
                "--program-dir",
                str(HEADER_PACKAGE),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    finally:
        if original is None:
            HEADER_PACKAGE_PROVER.unlink(missing_ok=True)
        else:
            HEADER_PACKAGE_PROVER.write_text(original, encoding="utf-8")
        (ROOT / "target" / f"{witness_name}.gz").unlink(missing_ok=True)


def _header_witness_inputs() -> dict[str, object]:
    fixture = load_default_header_anchor_fixtures()[0]
    return build_header_anchor_witness(fixture)


def test_header_anchor_fixture_loader_reports_uniform_real_and_synthetic_headers() -> None:
    fixtures = load_default_header_anchor_fixtures()
    report = header_uniformity_report(fixtures)

    assert [fixture.fixture_id for fixture in fixtures] == [
        "hoodi_block_9_reconstructed",
        "hoodi_block_9_extraData_2bytes",
        "hoodi_block_9_extraData_31bytes",
    ]
    assert report.fixture_count == 3
    assert report.field_count == 20
    assert report.min_header_len == 577
    assert report.max_header_len == 608
    assert report.layout_signature == (
        "parentHash",
        "sha3Uncles",
        "miner",
        "stateRoot",
        "transactionsRoot",
        "receiptsRoot",
        "logsBloom",
        "difficulty",
        "number",
        "gasLimit",
        "gasUsed",
        "timestamp",
        "extraData",
        "mixHash",
        "nonce",
        "baseFeePerGas",
        "withdrawalsRoot",
        "blobGasUsed",
        "excessBlobGas",
        "parentBeaconBlockRoot",
    )


def test_real_hoodi_block_headers_uniformity_and_capacity() -> None:
    records = _parse_real_hoodi_headers()
    lengths = [int(record["header_len"]) for record in records]
    field_counts = {int(record["field_count"]) for record in records}
    block_numbers = [int(record["block_number"]) for record in records]

    assert len(records) == 11
    assert block_numbers == list(range(11))
    assert field_counts == {20}
    assert min(lengths) == 577
    assert max(lengths) == 602
    assert lengths.index(max(lengths)) == 6
    assert all(length <= MAX_HEADER_BYTES for length in lengths)
    assert MAX_HEADER_BYTES == 640
    assert all(len(record["state_root"]) == 32 for record in records)


def test_header_anchor_noir_and_python_capacity_constants_match() -> None:
    noir_capacity = (HEADER_PACKAGE / "src" / "expanded_header_capacity.nr").read_text(encoding="utf-8")
    assert f"global MAX_HEADER_BYTES: u32 = {MAX_HEADER_BYTES};" in noir_capacity
    assert f"global EXPECTED_HEADER_FIELD_COUNT: u32 = {EXPECTED_HEADER_FIELD_COUNT};" in noir_capacity
    assert "global WITNESS_VERSION: u32 = 1;" in noir_capacity


@pytest.mark.parametrize("fixture_id", ["hoodi_block_9_reconstructed", "hoodi_block_9_extraData_2bytes", "hoodi_block_9_extraData_31bytes"])
def test_header_anchor_fixture_validates_and_builds_witness(fixture_id: str) -> None:
    fixture = next(fixture for fixture in load_default_header_anchor_fixtures() if fixture.fixture_id == fixture_id)
    validation = validate_header_fixture(fixture)
    witness = build_header_anchor_witness(fixture)

    assert validation.header_ready
    assert validation.header_hash_matches
    assert validation.state_root_matches
    assert witness["witness_version"] == 1
    assert witness["public_block_hash"] == [int(byte) for byte in bytes.fromhex(fixture.block_hash[2:])]
    assert witness["public_expected_state_root"] == [int(byte) for byte in bytes.fromhex(fixture.state_root[2:])]
    assert len(witness["private_header_bytes"]) == 640
    assert witness["private_header_len"] == fixture.header_rlp_len
    assert all(byte == 0 for byte in witness["private_header_bytes"][fixture.header_rlp_len :])


def test_header_anchor_prover_toml_round_trips() -> None:
    fixture = load_default_header_anchor_fixtures()[0]
    target = ROOT / "target" / "header_anchor_test_prover.toml"
    try:
        write_header_anchor_prover_toml(target, fixture)
        parsed = tomllib.loads(target.read_text(encoding="utf-8"))
    finally:
        target.unlink(missing_ok=True)

    assert parsed["witness_version"] == 1
    assert parsed["private_header_len"] == fixture.header_rlp_len
    assert parsed["public_block_hash"][0] == int(fixture.block_hash[2:4], 16)


def test_header_anchor_rejects_wrong_header_hash() -> None:
    fixture = load_default_header_anchor_fixtures()[0]
    wrong = replace(fixture, block_hash="0x" + "00" * 32)

    with pytest.raises(ValueError, match="failed validation"):
        build_header_anchor_witness(wrong)


def test_header_anchor_wrong_block_hash_execute_is_rejected() -> None:
    noir_inputs = _header_witness_inputs()
    noir_inputs["public_block_hash"] = [0] * 32

    result = _run_header_execute(noir_inputs, "header_anchor_wrong_block_hash")

    assert result.returncode != 0
    assert result.stderr or result.stdout


def test_header_anchor_mutated_active_header_byte_execute_is_rejected() -> None:
    noir_inputs = _header_witness_inputs()
    noir_inputs["private_header_bytes"][0] ^= 1

    result = _run_header_execute(noir_inputs, "header_anchor_mutated_header_byte")

    assert result.returncode != 0
    assert result.stderr or result.stdout


def test_header_anchor_wrong_expected_state_root_execute_is_rejected() -> None:
    noir_inputs = _header_witness_inputs()
    noir_inputs["public_expected_state_root"] = [0] * 32

    result = _run_header_execute(noir_inputs, "header_anchor_wrong_expected_state_root")

    assert result.returncode != 0
    assert result.stderr or result.stdout
