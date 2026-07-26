fn as_u32(value: Field) -> u32 {
    let converted = value as u32;
    assert(value == converted as Field);
    converted
}

fn byte_at(input: [u8; 1024], index: Field) -> u8 {
    let idx = as_u32(index);
    assert(idx < 256);
    input[idx]
}

fn assert_layout_range(layout: [Field; 4], node_len: Field) {
    let encoded_offset = as_u32(layout[0]);
    let encoded_len = as_u32(layout[1]);
    let payload_offset = as_u32(layout[2]);
    let payload_len = as_u32(layout[3]);
    let node_len_u32 = as_u32(node_len);

    assert(encoded_len > 0);
    assert(encoded_offset + encoded_len <= node_len_u32);
    assert(payload_offset >= encoded_offset);
    assert(payload_offset + payload_len <= encoded_offset + encoded_len);
}

fn assert_single_byte_item(input: [u8; 1024], layout: [Field; 4], node_len: Field) {
    assert_layout_range(layout, node_len);
    assert(layout[1] == 1);
    assert(layout[2] == layout[0]);
    assert(layout[3] == 1);
    assert(byte_at(input, layout[0]) < 128);
}

fn assert_string_item(input: [u8; 1024], layout: [Field; 4], node_len: Field) {
    assert_layout_range(layout, node_len);
    let prefix = byte_at(input, layout[0]) as Field;
    let payload_len = layout[3];
    let payload_len_u32 = as_u32(payload_len);

    if layout[1] == 1 {
        if payload_len_u32 == 1 {
            assert_single_byte_item(input, layout, node_len);
        } else {
            assert(payload_len_u32 == 0);
            assert(byte_at(input, layout[0]) == 128);
            assert(layout[2] == layout[0] + 1);
        }
    } else if payload_len_u32 <= 55 {
        assert(prefix == 128 + (payload_len as Field));
        assert(layout[2] == layout[0] + 1);
        assert(layout[1] == payload_len + 1);
    } else {
        // This bounded circuit supports the one-byte long-form RLP length used
        // by account values up to the full UInt256 balance case.
        assert(prefix == 184);
        assert(byte_at(input, layout[0] + 1) as Field == payload_len);
        assert(layout[2] == layout[0] + 2);
        assert(layout[1] == payload_len + 2);
    }
}

fn assert_list_item(input: [u8; 1024], layout: [Field; 4], node_len: Field) {
    assert_layout_range(layout, node_len);
    let prefix = byte_at(input, layout[0]) as Field;
    let payload_len = layout[3];
    let payload_len_u32 = as_u32(payload_len);

    if payload_len_u32 <= 55 {
        assert(prefix == 192 + payload_len);
        assert(layout[2] == layout[0] + 1);
        assert(layout[1] == payload_len + 1);
    } else {
        assert(prefix == 248);
        assert(byte_at(input, layout[0] + 1) as Field == payload_len);
        assert(layout[2] == layout[0] + 2);
        assert(layout[1] == payload_len + 2);
    }
}

fn assert_adjacent(left: [Field; 4], right: [Field; 4]) {
    assert(right[0] == left[0] + left[1]);
}

fn u64_from_be_bytes(bytes: [u8; 8]) -> u64 {
    let mut value: u64 = 0;
    for i in 0..8 {
        value = value * 256 + (bytes[i] as u64);
    }
    value
}

fn bytes32_to_u64_limbs(bytes: [u8; 32]) -> [u64; 4] {
    let mut limbs: [u64; 4] = [0; 4];
    for limb_index in 0..4 {
        let mut chunk: [u8; 8] = [0; 8];
        for byte_index in 0..8 {
            chunk[byte_index] = bytes[limb_index * 8 + byte_index];
        }
        limbs[limb_index] = u64_from_be_bytes(chunk);
    }
    limbs
}

fn balance_payload_to_bytes32(
    input: [u8; 1024],
    balance_layout: [Field; 4],
) -> [u8; 32] {
    let encoded_offset = as_u32(balance_layout[0]);
    let encoded_len = as_u32(balance_layout[1]);
    let payload_offset = as_u32(balance_layout[2]);
    let payload_len = as_u32(balance_layout[3]);
    assert(payload_len <= 32);
    assert_layout_range(balance_layout, 1024);

    let mut value: [u8; 32] = [0; 32];
    if payload_len == 0 {
        assert(encoded_len == 1);
        assert(byte_at(input, encoded_offset as Field) == 128);
    } else if encoded_len == 1 {
        let encoded_value = byte_at(input, encoded_offset as Field);
        assert(encoded_value > 0);
        assert(encoded_value < 128);
        value[31] = encoded_value;
    } else {
        let prefix = byte_at(input, encoded_offset as Field) as Field;
        assert(prefix == 128 + (payload_len as Field));
        if payload_len == 1 {
            assert(byte_at(input, payload_offset as Field) >= 128);
        } else {
            assert(byte_at(input, payload_offset as Field) != 0);
        }
        for i in 0..32 {
            if i < 32 - payload_len {
                value[i] = 0;
            } else {
                let source = payload_offset + (i - (32 - payload_len));
                value[i] = byte_at(input, source as Field);
            }
        }
    }
    value
}

fn balance_payload_to_u64_limbs(
    input: [u8; 1024],
    balance_layout: [Field; 4],
) -> [u64; 4] {
    bytes32_to_u64_limbs(balance_payload_to_bytes32(input, balance_layout))
}

fn assert_balance_payload_equals_claim_limbs(
    input: [u8; 1024],
    balance_layout: [Field; 4],
    claimed_balance_limbs: [u64; 4],
) {
    let actual_limbs = balance_payload_to_u64_limbs(input, balance_layout);
    for i in 0..4 {
        assert(actual_limbs[i] == claimed_balance_limbs[i]);
    }
}

pub fn assert_account_balance_layout(
    leaf_node: [u8; 1024],
    leaf_node_len: Field,
    claimed_balance_limbs: [u64; 4],
    leaf_outer_list: [Field; 4],
    leaf_compact_path: [Field; 4],
    leaf_account_value: [Field; 4],
    account_inner_list: [Field; 4],
    account_nonce: [Field; 4],
    account_balance: [Field; 4],
    account_storage_root: [Field; 4],
    account_code_hash: [Field; 4],
) {
    assert_list_item(leaf_node, leaf_outer_list, leaf_node_len);
    assert(leaf_outer_list[0] == 0);
    assert(leaf_outer_list[1] == leaf_node_len);

    assert_string_item(leaf_node, leaf_compact_path, leaf_node_len);
    assert_string_item(leaf_node, leaf_account_value, leaf_node_len);
    assert(leaf_compact_path[0] == leaf_outer_list[2]);
    assert_adjacent(leaf_compact_path, leaf_account_value);
    assert(leaf_account_value[0] + leaf_account_value[1] == leaf_outer_list[2] + leaf_outer_list[3]);

    assert_list_item(leaf_node, account_inner_list, leaf_node_len);
    assert(account_inner_list[0] == leaf_account_value[2]);
    assert(account_inner_list[1] == leaf_account_value[3]);

    assert_string_item(leaf_node, account_nonce, leaf_node_len);
    assert_string_item(leaf_node, account_balance, leaf_node_len);
    assert_string_item(leaf_node, account_storage_root, leaf_node_len);
    assert_string_item(leaf_node, account_code_hash, leaf_node_len);

    assert(account_nonce[0] == account_inner_list[2]);
    assert_adjacent(account_nonce, account_balance);
    assert_adjacent(account_balance, account_storage_root);
    assert_adjacent(account_storage_root, account_code_hash);
    assert(account_code_hash[0] + account_code_hash[1] == account_inner_list[2] + account_inner_list[3]);

    assert(account_storage_root[3] == 32);
    assert(account_code_hash[3] == 32);

    assert_balance_payload_equals_claim_limbs(leaf_node, account_balance, claimed_balance_limbs);
}

#[test]
fn test_zero_balance_layout() {
    let mut input = [0; 1024];
    input[0] = 248;
    input[1] = 73;
    input[2] = 128;
    input[3] = 184;
    input[4] = 70;
    input[5] = 248;
    input[6] = 68;
    input[7] = 128;
    input[8] = 128;
    input[9] = 160;
    input[42] = 160;
    assert_account_balance_layout(
        input,
        75,
        [0, 0, 0, 0],
        [0, 75, 2, 73],
        [2, 1, 3, 0],
        [3, 72, 5, 70],
        [5, 70, 7, 68],
        [7, 1, 8, 0],
        [8, 1, 9, 0],
        [9, 33, 10, 32],
        [42, 33, 43, 32],
    );
}

#[test]
fn test_bytes32_to_u64_limbs_boundaries() {
    let mut bytes = [0; 32];
    bytes[23] = 1;
    bytes[31] = 1;
    let limbs = bytes32_to_u64_limbs(bytes);
    assert(limbs[0] == 0);
    assert(limbs[1] == 0);
    assert(limbs[2] == 1);
    assert(limbs[3] == 1);

    let mut bytes = [0; 32];
    bytes[15] = 1;
    bytes[31] = 1;
    let limbs = bytes32_to_u64_limbs(bytes);
    assert(limbs[0] == 0);
    assert(limbs[1] == 1);
    assert(limbs[2] == 0);
    assert(limbs[3] == 1);

    let mut bytes = [0; 32];
    bytes[7] = 1;
    bytes[31] = 1;
    let limbs = bytes32_to_u64_limbs(bytes);
    assert(limbs[0] == 1);
    assert(limbs[1] == 0);
    assert(limbs[2] == 0);
    assert(limbs[3] == 1);
}

#[test(should_fail)]
fn test_wrong_zero_balance_claim_fails() {
    let mut input = [0; 1024];
    input[0] = 248;
    input[1] = 73;
    input[2] = 128;
    input[3] = 184;
    input[4] = 70;
    input[5] = 248;
    input[6] = 68;
    input[7] = 128;
    input[8] = 128;
    input[9] = 160;
    input[42] = 160;

    let claimed_balance_limbs = [0, 0, 0, 1];

    assert_account_balance_layout(
        input,
        75,
        claimed_balance_limbs,
        [0, 75, 2, 73],
        [2, 1, 3, 0],
        [3, 72, 5, 70],
        [5, 70, 7, 68],
        [7, 1, 8, 0],
        [8, 1, 9, 0],
        [9, 33, 10, 32],
        [42, 33, 43, 32],
    );
}

#[test(should_fail)]
fn test_account_value_not_second_item_fails() {
    let mut input = [0; 1024];
    input[0] = 248;
    input[1] = 73;
    input[2] = 128;
    input[3] = 184;
    input[4] = 70;
    input[5] = 248;
    input[6] = 68;
    input[7] = 128;
    input[8] = 128;
    input[9] = 160;
    input[42] = 160;

    assert_account_balance_layout(
        input,
        75,
        [0, 0, 0, 0],
        [0, 75, 2, 73],
        [3, 72, 5, 70],
        [2, 1, 3, 0],
        [5, 70, 7, 68],
        [7, 1, 8, 0],
        [8, 1, 9, 0],
        [9, 33, 10, 32],
        [42, 33, 43, 32],
    );
}
