from pathlib import Path
import re

from thesis_c.proof_inputs import expanded_mpt_capacity as capacity


ROOT = Path(__file__).parents[1]


def test_capacity_profile_and_generated_modules_are_current():
    expected = []
    for name in capacity.CAPACITY_NAMES:
        expected.append(f"global {name}: u32 = {getattr(capacity, name)};")
    for relative in (
        "circuits_mpt_inclusion/src/expanded_mpt_capacity.nr",
        "circuits_mpt_inclusion_poseidon2/src/expanded_mpt_capacity.nr",
    ):
        text = (ROOT / relative).read_text()
        for line in expected:
            assert line in text


def test_expanded_capacity_bounds_are_decision_complete():
    assert capacity.MAX_PROOF_NODES == 16
    assert capacity.MAX_NODE_RLP_BYTES == 1024
    assert capacity.MAX_TOTAL_PROOF_RLP_BYTES == 8192
    assert capacity.MAX_EXTENSION_NODES == 8
    assert capacity.MAX_TERMINAL_VALUE_BYTES == 256
    assert capacity.ACCOUNT_KEY_BYTES == 32
    assert capacity.ACCOUNT_PATH_NIBBLES == 64
    assert capacity.MAX_COMPACT_PATH_BYTES == 33
    assert capacity.BRANCH_CHILD_SLOTS == 16
    assert capacity.WITNESS_VERSION == 1


def _normalized_core(path: Path) -> str:
    text = path.read_text()
    text = text.split("fn root_leaf_fixture", 1)[0]
    text = re.sub(r"crate::hash_(keccak|poseidon2)::hash_node", "HASH_NODE", text)
    text = re.sub(r"crate::hash_poseidon2::bytes32_to_field", "ROOT_BRIDGE", text)
    text = re.sub(r"\s*private_state_root_field: Field,", "", text)
    text = re.sub(r"\s*assert\(ROOT_BRIDGE\(public_state_root\) == private_state_root_field\);", "", text)
    text = re.sub(r"\s*assert\(HASH_NODE\(node_bytes\[0\], node_lengths\[0\]\) == private_state_root_field\);", "", text)
    text = re.sub(r"\s*assert\(HASH_NODE\(node_bytes\[0\], node_lengths\[0\]\) == public_state_root\);", "", text)
    text = text.replace(
        "HASH_NODE(node_bytes[i + 1], node_lengths[i + 1]) == ROOT_BRIDGE(selected_ref_bytes[i])",
        "HASH_NODE(node_bytes[i + 1], node_lengths[i + 1]) == selected_ref_bytes[i]",
    )
    return text


def test_keccak_poseidon2_structural_core_parity():
    keccak = _normalized_core(ROOT / "circuits_mpt_inclusion/src/mpt_inclusion.nr")
    poseidon = _normalized_core(ROOT / "circuits_mpt_inclusion_poseidon2/src/mpt_inclusion.nr")
    assert keccak == poseidon


def test_parity_includes_required_structural_operations():
    text = _normalized_core(ROOT / "circuits_mpt_inclusion/src/mpt_inclusion.nr")
    for required in (
        "active_node_count",
        "max_total_proof_rlp_bytes",
        "extension_count",
        "node_item_layouts",
        "selected_ref_layouts",
        "selected_ref_kinds",
        "terminal_value",
        "assert_compact",
        "assert_bytes_equal",
    ):
        assert required in text
