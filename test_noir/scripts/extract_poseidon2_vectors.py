#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
P = int("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, cwd=ROOT, check=True, text=True, capture_output=True).stdout


def as_hex(value: int) -> str:
    if value < 0 or value >= P:
        raise ValueError(f"field element out of range: {value}")
    return f"0x{value:064x}"


def as_modulus_hex() -> str:
    return f"0x{P:064x}"


def as_bytes_hex(values: list[int]) -> str:
    return "0x" + "".join(f"{value:02x}" for value in values)


def field_to_be_bytes_hex(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def normalize(obj):
    if isinstance(obj, int):
        return as_hex(obj)
    if isinstance(obj, tuple):
        return [normalize(item) for item in obj]
    if isinstance(obj, list):
        return [normalize(item) for item in obj]
    raise TypeError(f"unsupported value type: {type(obj)!r}")


def parse_output(stdout: str):
    match = re.search(r"Circuit output:\s*(.*)\s*$", stdout, re.S)
    if not match:
        raise RuntimeError(f"could not find circuit output in:\n{stdout}")
    return ast.literal_eval(match.group(1))


def main() -> None:
    nargo_version = run(["nargo", "--version"]).strip()
    execute_stdout = run(["nargo", "execute", "--overwrite-return", "--prover-name", "Prover"])
    parsed = parse_output(execute_stdout)
    if len(parsed) != 19:
        raise RuntimeError(f"expected 19 top-level circuit outputs, got {len(parsed)}")

    field_section = parsed[:18]
    byte_section = parsed[18]
    if len(byte_section) != 17:
        raise RuntimeError(f"expected 17 byte-vector outputs, got {len(byte_section)}")

    (
        raw_permutation,
        fixed_empty,
        fixed_0,
        fixed_1,
        fixed_2,
        fixed_3,
        fixed_4,
        fixed_5,
        fixed_8,
        fixed_p_minus_one,
        variable_size_0,
        variable_size_1,
        variable_size_2,
        variable_size_3,
        variable_size_4,
        pad_a,
        pad_b,
        pad_control,
    ) = field_section

    byte_case_names = [
        "empty",
        "one_zero",
        "one_one",
        "one_ff",
        "two_bytes",
        "trailing_zero_ambiguity_a",
        "trailing_zero_ambiguity_b",
        "trailing_zero_ambiguity_c",
        "thirty_one_bytes",
        "thirty_two_bytes",
        "thirty_three_bytes",
        "sixty_two_bytes",
        "sixty_three_bytes",
        "sixty_four_bytes",
        "twenty_byte_address_like",
        "thirty_two_byte_storage_key_like",
        "rlp_like_short_sequence",
    ]
    byte_inputs = [
        [],
        [0x00],
        [0x01],
        [0xff],
        [0x01, 0x02],
        [0x01],
        [0x01, 0x00],
        [0x01, 0x00, 0x00],
        list(range(0x00, 0x1f)),
        list(range(0x00, 0x20)),
        list(range(0x00, 0x21)),
        list(range(0x00, 0x3e)),
        list(range(0x00, 0x3f)),
        list(range(0x00, 0x40)),
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40],
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            0xd0, 0xe0, 0xf0, 0x01,
        ],
        [0xc8, 0x01, 0x02, 0x83, 0x61, 0x62, 0x63],
    ]
    byte_cases = []
    for index, (name, input_bytes, case_output) in enumerate(zip(byte_case_names, byte_inputs, byte_section)):
        packed_fields, packed_count, output_field = case_output
        if packed_count != (len(input_bytes) + 30) // 31:
            raise RuntimeError(
                f"packed field count mismatch for {name}: expected {(len(input_bytes) + 30) // 31}, got {packed_count}"
            )
        trimmed_packed_fields = packed_fields[:packed_count]
        output_hex = as_hex(output_field)
        byte_cases.append(
            {
                "case_name": name,
                "input_bytes_hex": as_bytes_hex(input_bytes),
                "packed_fields_hex": [as_hex(value) for value in trimmed_packed_fields],
                "packed_field_count": packed_count,
                "output_field_hex": output_hex,
                "output_bytes_be_hex": field_to_be_bytes_hex(output_field),
            }
        )

    field_data = {
        "repository": "noir-lang/poseidon",
        "tag": "v0.3.0",
        "commit": "0880c371e88e583d39515fd3f877538657ac41eb",
        "nargo_version": nargo_version,
        "bb_version": None,
        "field_modulus": as_modulus_hex(),
        "raw_permutation": {
            "input": [as_hex(0), as_hex(1), as_hex(2), as_hex(3)],
            "output": normalize(raw_permutation),
        },
        "fixed_length_vectors": [
            {"input": [], "message_size": 0, "output": as_hex(fixed_empty)},
            {"input": [as_hex(0)], "message_size": 1, "output": as_hex(fixed_0)},
            {"input": [as_hex(1)], "message_size": 1, "output": as_hex(fixed_1)},
            {"input": [as_hex(0), as_hex(1)], "message_size": 2, "output": as_hex(fixed_2)},
            {
                "input": [as_hex(0), as_hex(1), as_hex(2)],
                "message_size": 3,
                "output": as_hex(fixed_3),
            },
            {
                "input": [as_hex(0), as_hex(1), as_hex(2), as_hex(3)],
                "message_size": 4,
                "output": as_hex(fixed_4),
            },
            {
                "input": [as_hex(0), as_hex(1), as_hex(2), as_hex(3), as_hex(4)],
                "message_size": 5,
                "output": as_hex(fixed_5),
            },
            {
                "input": [as_hex(P - 1)],
                "message_size": 1,
                "output": as_hex(fixed_p_minus_one),
            },
            {
                "input": [as_hex(0), as_hex(1), as_hex(2), as_hex(3), as_hex(4), as_hex(5), as_hex(6), as_hex(7)],
                "message_size": 8,
                "output": as_hex(fixed_8),
            },
        ],
        "variable_length_vectors": [
            {
                "input": [as_hex(0), as_hex(0), as_hex(0), as_hex(0), as_hex(0)],
                "message_size": 0,
                "output": as_hex(fixed_empty),
            },
            {
                "input": [as_hex(1), as_hex(0), as_hex(0), as_hex(0), as_hex(0)],
                "message_size": 1,
                "output": as_hex(variable_size_1),
            },
            {
                "input": [as_hex(1), as_hex(2), as_hex(0), as_hex(0), as_hex(0)],
                "message_size": 2,
                "output": as_hex(variable_size_2),
            },
            {
                "input": [as_hex(1), as_hex(2), as_hex(3), as_hex(0), as_hex(0)],
                "message_size": 3,
                "output": as_hex(variable_size_3),
            },
            {
                "input": [as_hex(1), as_hex(2), as_hex(3), as_hex(4), as_hex(0)],
                "message_size": 4,
                "output": as_hex(variable_size_4),
            },
            {
                "input": [as_hex(1), as_hex(2), as_hex(99), as_hex(98), as_hex(97)],
                "message_size": 2,
                "output": as_hex(pad_a),
            },
            {
                "input": [as_hex(1), as_hex(2), as_hex(11), as_hex(12), as_hex(13)],
                "message_size": 2,
                "output": as_hex(pad_b),
            },
            {
                "input": [as_hex(3), as_hex(2), as_hex(99), as_hex(98), as_hex(97)],
                "message_size": 2,
                "output": as_hex(pad_control),
            },
        ],
        "padding_equivalence": {
            "a": {
                "input": [as_hex(1), as_hex(2), as_hex(99), as_hex(98), as_hex(97)],
                "message_size": 2,
                "output": as_hex(pad_a),
            },
            "b": {
                "input": [as_hex(1), as_hex(2), as_hex(11), as_hex(12), as_hex(13)],
                "message_size": 2,
                "output": as_hex(pad_b),
            },
            "control": {
                "input": [as_hex(3), as_hex(2), as_hex(99), as_hex(98), as_hex(97)],
                "message_size": 2,
                "output": as_hex(pad_control),
            },
        },
    }

    byte_data = {
        "repository": "noir-lang/poseidon",
        "tag": "v0.3.0",
        "commit": "0880c371e88e583d39515fd3f877538657ac41eb",
        "nargo_version": nargo_version,
        "bb_version": None,
        "field_modulus": as_modulus_hex(),
        "packing_rule": {
            "chunk_size_bytes": 31,
            "endianness": "little",
            "final_partial_chunk_padding": "zero",
            "length_field": False,
            "domain_separator": False,
        },
        "cases": byte_cases,
    }

    sponge_out_path = ROOT / "poseidon2_sponge_vectors.json"
    byte_out_path = ROOT / "poseidon2_byte_vectors.json"
    sponge_out_path.write_text(json.dumps(field_data, indent=2) + "\n")
    byte_out_path.write_text(json.dumps(byte_data, indent=2) + "\n")

    fixed = field_data["fixed_length_vectors"]
    variable = field_data["variable_length_vectors"]
    padding = field_data["padding_equivalence"]

    if variable[0]["output"] != fixed[0]["output"]:
        raise RuntimeError("variable size 0 does not match fixed empty")
    if variable[1]["output"] != fixed[2]["output"]:
        raise RuntimeError("variable size 1 does not match fixed [1]")
    if variable[2]["output"] != "0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383":
        raise RuntimeError("variable size 2 output changed")
    if variable[3]["output"] != "0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8":
        raise RuntimeError("variable size 3 output changed")
    if variable[4]["output"] != "0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9":
        raise RuntimeError("variable size 4 output changed")
    if padding["a"]["output"] != padding["b"]["output"]:
        raise RuntimeError("padding A and B do not match")
    if padding["control"]["output"] == padding["a"]["output"]:
        raise RuntimeError("padding control unexpectedly matches padding A")

    empty_case = byte_cases[0]
    zero_case = byte_cases[1]
    one_case = byte_cases[2]
    one_zero_case = byte_cases[6]
    one_zero_zero_case = byte_cases[7]

    if empty_case["output_field_hex"] == zero_case["output_field_hex"]:
        raise RuntimeError("empty bytes unexpectedly collide with [00]")
    if one_case["output_field_hex"] != one_zero_case["output_field_hex"]:
        raise RuntimeError("[01] and [01 00] do not collide as expected")
    if one_case["output_field_hex"] != one_zero_zero_case["output_field_hex"]:
        raise RuntimeError("[01] and [01 00 00] do not collide as expected")

    boundary_counts = {
        "thirty_one_bytes": 1,
        "thirty_two_bytes": 2,
        "thirty_three_bytes": 2,
        "sixty_two_bytes": 2,
        "sixty_three_bytes": 3,
        "sixty_four_bytes": 3,
    }
    for case in byte_cases:
        expected_count = (len(bytes.fromhex(case["input_bytes_hex"][2:])) + 30) // 31
        if case["packed_field_count"] != expected_count:
            raise RuntimeError(f"unexpected packed field count for {case['case_name']}")
        if case["case_name"] in boundary_counts and case["packed_field_count"] != boundary_counts[case["case_name"]]:
            raise RuntimeError(f"boundary packed field count mismatch for {case['case_name']}")


if __name__ == "__main__":
    main()
