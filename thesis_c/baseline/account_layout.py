from __future__ import annotations

from dataclasses import dataclass


UINT256_MAX = (1 << 256) - 1
UINT64_MAX = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class RlpItemLayout:
    encoded_offset: int
    encoded_len: int
    payload_offset: int
    payload_len: int
    prefix_form: str
    is_single_byte: bool


@dataclass(frozen=True, slots=True)
class LeafNodeLayout:
    outer_list: RlpItemLayout
    compact_path_item: RlpItemLayout
    account_value_item: RlpItemLayout


@dataclass(frozen=True, slots=True)
class AccountValueLayout:
    inner_list: RlpItemLayout
    nonce: RlpItemLayout
    balance: RlpItemLayout
    storage_root: RlpItemLayout
    code_hash: RlpItemLayout


def parse_rpc_quantity(value: int | str) -> int:
    if isinstance(value, int):
        parsed = value
    else:
        text = value.strip().lower()
        parsed = int(text[2:] or "0", 16) if text.startswith("0x") else int(text)
    if parsed < 0 or parsed > UINT256_MAX:
        raise ValueError("Balance must be a UInt256 value.")
    return parsed


def uint256_to_bytes32(value: int | str) -> bytes:
    return parse_rpc_quantity(value).to_bytes(32, "big")


def uint256_to_u64_limbs(value: int | str) -> tuple[int, int, int, int]:
    parsed = parse_rpc_quantity(value)
    return (
        (parsed >> 192) & UINT64_MAX,
        (parsed >> 128) & UINT64_MAX,
        (parsed >> 64) & UINT64_MAX,
        parsed & UINT64_MAX,
    )


def u64_limbs_to_uint256(limbs: list[int] | tuple[int, int, int, int]) -> int:
    if len(limbs) != 4:
        raise ValueError("UInt256 limb representation must contain exactly four limbs.")

    value = 0
    for limb in limbs:
        if limb < 0 or limb > UINT64_MAX:
            raise ValueError("UInt64 limb is out of range.")
        value = (value << 64) | limb
    return value


def u64_limbs_to_bytes32(limbs: list[int] | tuple[int, int, int, int]) -> bytes:
    return u64_limbs_to_uint256(limbs).to_bytes(32, "big")


def canonical_uint_rlp_item(value: int | str) -> bytes:
    parsed = parse_rpc_quantity(value)
    if parsed == 0:
        return b"\x80"
    payload = parsed.to_bytes((parsed.bit_length() + 7) // 8, "big")
    if len(payload) == 1 and payload[0] < 0x80:
        return payload
    return bytes([0x80 + len(payload)]) + payload


def assert_canonical_uint_rlp_item(encoded: bytes) -> int:
    if not encoded:
        raise ValueError("Empty RLP item is not a complete encoded scalar.")
    first = encoded[0]
    if first < 0x80:
        if len(encoded) != 1:
            raise ValueError("Single-byte scalar has trailing bytes.")
        if first == 0:
            raise ValueError("Canonical account zero must use empty-string RLP 0x80.")
        return first
    if first == 0x80:
        if len(encoded) != 1:
            raise ValueError("Canonical zero must be exactly 0x80.")
        return 0
    if first <= 0xA0:
        payload_len = first - 0x80
        payload = encoded[1:]
        if len(payload) != payload_len:
            raise ValueError("RLP scalar payload length mismatch.")
        if payload_len == 0:
            raise ValueError("Zero must use 0x80.")
        if payload[0] == 0:
            raise ValueError("UInt scalar payload has a leading zero.")
        if payload_len == 1 and payload[0] < 0x80:
            raise ValueError("Values below 0x80 must use single-byte RLP form.")
        if payload_len > 32:
            raise ValueError("UInt scalar exceeds 32 bytes.")
        return int.from_bytes(payload, "big")
    raise ValueError("UInt256 account scalar must use short RLP string form.")


def parse_rlp_item(data: bytes, offset: int) -> RlpItemLayout:
    if offset < 0 or offset >= len(data):
        raise ValueError("RLP item offset is out of bounds.")
    first = data[offset]
    if first < 0x80:
        return RlpItemLayout(offset, 1, offset, 1, "single", True)
    if first <= 0xB7:
        payload_len = first - 0x80
        encoded_len = 1 + payload_len
        _assert_in_bounds(data, offset, encoded_len)
        return RlpItemLayout(offset, encoded_len, offset + 1, payload_len, "short_string", False)
    if first <= 0xBF:
        len_of_len = first - 0xB7
        _assert_in_bounds(data, offset + 1, len_of_len)
        payload_len = int.from_bytes(data[offset + 1 : offset + 1 + len_of_len], "big")
        encoded_len = 1 + len_of_len + payload_len
        _assert_in_bounds(data, offset, encoded_len)
        return RlpItemLayout(
            offset,
            encoded_len,
            offset + 1 + len_of_len,
            payload_len,
            "long_string",
            False,
        )
    if first <= 0xF7:
        payload_len = first - 0xC0
        encoded_len = 1 + payload_len
        _assert_in_bounds(data, offset, encoded_len)
        return RlpItemLayout(offset, encoded_len, offset + 1, payload_len, "short_list", False)

    len_of_len = first - 0xF7
    _assert_in_bounds(data, offset + 1, len_of_len)
    payload_len = int.from_bytes(data[offset + 1 : offset + 1 + len_of_len], "big")
    encoded_len = 1 + len_of_len + payload_len
    _assert_in_bounds(data, offset, encoded_len)
    return RlpItemLayout(offset, encoded_len, offset + 1 + len_of_len, payload_len, "long_list", False)


def parse_leaf_node_layout(leaf_node_rlp: bytes) -> LeafNodeLayout:
    outer = parse_rlp_item(leaf_node_rlp, 0)
    if not outer.prefix_form.endswith("_list"):
        raise ValueError("Terminal MPT leaf node must be an RLP list.")
    if outer.encoded_len != len(leaf_node_rlp):
        raise ValueError("Leaf node RLP has trailing bytes.")

    compact_path = parse_rlp_item(leaf_node_rlp, outer.payload_offset)
    account_value = parse_rlp_item(leaf_node_rlp, compact_path.encoded_offset + compact_path.encoded_len)
    if account_value.encoded_offset + account_value.encoded_len != outer.payload_offset + outer.payload_len:
        raise ValueError("Leaf node must contain exactly two items.")
    if account_value.prefix_form not in {"short_string", "long_string"}:
        raise ValueError("Account value must be an RLP byte-string item.")

    return LeafNodeLayout(outer, compact_path, account_value)


def parse_account_value_layout(leaf_node_rlp: bytes, leaf_layout: LeafNodeLayout) -> AccountValueLayout:
    account_payload_start = leaf_layout.account_value_item.payload_offset
    inner = parse_rlp_item(leaf_node_rlp, account_payload_start)
    if not inner.prefix_form.endswith("_list"):
        raise ValueError("Account value payload must be an RLP list.")
    if inner.encoded_len != leaf_layout.account_value_item.payload_len:
        raise ValueError("Account value item payload must be exactly the inner account list.")

    items: list[RlpItemLayout] = []
    offset = inner.payload_offset
    end = inner.payload_offset + inner.payload_len
    while offset < end:
        item = parse_rlp_item(leaf_node_rlp, offset)
        items.append(item)
        offset = item.encoded_offset + item.encoded_len
    if offset != end:
        raise ValueError("Account list item ranges do not match declared payload.")
    if len(items) != 4:
        raise ValueError(f"Account value must contain exactly four fields, got {len(items)}.")

    storage_root = items[2]
    code_hash = items[3]
    if storage_root.payload_len != 32:
        raise ValueError("Account storageRoot payload must be 32 bytes.")
    if code_hash.payload_len != 32:
        raise ValueError("Account codeHash payload must be 32 bytes.")

    return AccountValueLayout(inner, items[0], items[1], storage_root, code_hash)


def parse_nested_account_layout(leaf_node_rlp: bytes) -> tuple[LeafNodeLayout, AccountValueLayout]:
    leaf_layout = parse_leaf_node_layout(leaf_node_rlp)
    account_layout = parse_account_value_layout(leaf_node_rlp, leaf_layout)
    return leaf_layout, account_layout


def encoded_slice(data: bytes, layout: RlpItemLayout) -> bytes:
    return data[layout.encoded_offset : layout.encoded_offset + layout.encoded_len]


def payload_slice(data: bytes, layout: RlpItemLayout) -> bytes:
    return data[layout.payload_offset : layout.payload_offset + layout.payload_len]


def _assert_in_bounds(data: bytes, offset: int, length: int) -> None:
    if length < 0 or offset < 0 or offset + length > len(data):
        raise ValueError("RLP item range is out of bounds.")
