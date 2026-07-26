fn as_u32(value: Field) -> u32 {
    let converted = value as u32;
    assert(value == converted as Field);
    converted
}

fn byte_at(input: [u8; 544], index: Field) -> u8 {
    let idx = as_u32(index);
    assert(idx < 544);
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

fn assert_single_byte_item(input: [u8; 544], layout: [Field; 4], node_len: Field) {
    assert_layout_range(layout, node_len);
    assert(layout[1] == 1);
    assert(layout[2] == layout[0]);
    assert(layout[3] == 1);
    assert(byte_at(input, layout[0]) < 128);
}

fn assert_string_item(input: [u8; 544], layout: [Field; 4], node_len: Field) {
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
        assert(prefix == 128 + payload_len);
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

fn assert_list_item(input: [u8; 544], layout: [Field; 4], node_len: Field) {
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

fn assert_zero_claim(claimed_balance: [u8; 32]) {
    for i in 0..32 {
        assert(claimed_balance[i] == 0);
    }
}

fn assert_balance_payload_equals_claim(
    input: [u8; 544],
    balance_layout: [Field; 4],
    claimed_balance: [u8; 32],
) {
    let payload_len = as_u32(balance_layout[3]);
    let payload_offset = as_u32(balance_layout[2]);
    assert(payload_len <= 32);

    for i in 0..32 {
        if i < 32 - payload_len {
            assert(claimed_balance[i] == 0);
        } else {
            let source = payload_offset + (i - (32 - payload_len));
            assert(claimed_balance[i] == input[source]);
        }
    }
}

pub fn assert_account_balance_layout(
    leaf_node: [u8; 544],
    leaf_node_len: Field,
    claimed_balance: [u8; 32],
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

    let balance_payload_len = account_balance[3];
    if balance_payload_len == 0 {
        assert(account_balance[1] == 1);
        assert(byte_at(leaf_node, account_balance[0]) == 128);
        assert_zero_claim(claimed_balance);
    } else if account_balance[1] == 1 {
        let value = byte_at(leaf_node, account_balance[0]);
        assert(value > 0);
        assert(value < 128);
        assert_balance_payload_equals_claim(leaf_node, account_balance, claimed_balance);
    } else {
        assert(as_u32(balance_payload_len) <= 32);
        assert(byte_at(leaf_node, account_balance[2]) != 0);
        if balance_payload_len == 1 {
            assert(byte_at(leaf_node, account_balance[2]) >= 128);
        }
        assert_balance_payload_equals_claim(leaf_node, account_balance, claimed_balance);
    }
}

pub fn assert_account_code_hash_layout(
    leaf_node: [u8; 544],
    leaf_node_len: Field,
    expected_code_hash: [u8; 32],
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
    assert(account_code_hash[1] == 33);
    assert(account_code_hash[2] == account_code_hash[0] + 1);
    assert(account_code_hash[3] == 32);
    assert(byte_at(leaf_node, account_code_hash[0]) == 160);

    let payload_offset = as_u32(account_code_hash[2]);
    for i in 0..32 {
        assert(leaf_node[payload_offset + i] == expected_code_hash[i]);
    }
}

#[test]
fn test_zero_balance_layout() {
    let mut input = [0; 544];
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
        [0; 32],
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
fn test_wrong_zero_balance_claim_fails() {
    let mut input = [0; 544];
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

    let mut claimed_balance = [0; 32];
    claimed_balance[31] = 1;

    assert_account_balance_layout(
        input,
        75,
        claimed_balance,
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
    let mut input = [0; 544];
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
        [0; 32],
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

#[test]
fn test_code_hash_layout_accepts_arbitrary_32_bytes() {
    let mut input = [0; 544];
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

    let mut expected = [0; 32];
    for i in 0..32 {
        expected[i] = (i + 1) as u8;
        input[43 + i] = expected[i];
    }

    assert_account_code_hash_layout(
        input,
        75,
        expected,
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
fn test_wrong_code_hash_fails() {
    let mut input = [0; 544];
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
    input[74] = 1;

    assert_account_code_hash_layout(
        input,
        75,
        [0; 32],
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
fn test_code_hash_payload_length_31_fails() {
    let mut input = [0; 544];
    input[0] = 248;
    input[1] = 72;
    input[2] = 128;
    input[3] = 184;
    input[4] = 69;
    input[5] = 248;
    input[6] = 67;
    input[7] = 128;
    input[8] = 128;
    input[9] = 160;
    input[42] = 159;

    assert_account_code_hash_layout(
        input,
        74,
        [0; 32],
        [0, 74, 2, 72],
        [2, 1, 3, 0],
        [3, 71, 5, 69],
        [5, 69, 7, 67],
        [7, 1, 8, 0],
        [8, 1, 9, 0],
        [9, 33, 10, 32],
        [42, 32, 43, 31],
    );
}

#[test(should_fail)]
fn test_code_hash_payload_length_33_fails() {
    let mut input = [0; 544];
    input[0] = 248;
    input[1] = 74;
    input[2] = 128;
    input[3] = 184;
    input[4] = 71;
    input[5] = 248;
    input[6] = 69;
    input[7] = 128;
    input[8] = 128;
    input[9] = 160;
    input[42] = 161;

    assert_account_code_hash_layout(
        input,
        76,
        [0; 32],
        [0, 76, 2, 74],
        [2, 1, 3, 0],
        [3, 73, 5, 71],
        [5, 71, 7, 69],
        [7, 1, 8, 0],
        [8, 1, 9, 0],
        [9, 33, 10, 32],
        [42, 34, 43, 33],
    );
}

#[test(should_fail)]
fn test_code_hash_prefix_not_a0_fails() {
    let mut input = [0; 544];
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
    input[42] = 159;

    assert_account_code_hash_layout(
        input,
        75,
        [0; 32],
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
fn test_code_hash_offset_pointing_to_storage_root_fails() {
    let mut input = [0; 544];
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

    assert_account_code_hash_layout(
        input,
        75,
        [0; 32],
        [0, 75, 2, 73],
        [2, 1, 3, 0],
        [3, 72, 5, 70],
        [5, 70, 7, 68],
        [7, 1, 8, 0],
        [8, 1, 9, 0],
        [42, 33, 43, 32],
        [9, 33, 10, 32],
    );
}
