fn as_u32(value: Field) -> u32 {
    let converted = value as u32;
    assert(value == converted as Field);
    converted
}

fn byte_at(input: [u8; 1024], index: Field) -> u8 {
    let idx = as_u32(index);
    assert(idx < 1024);
    input[idx]
}

fn nibble_at(input: [u8; 1024], byte_offset: Field, nibble_index: Field) -> Field {
    let idx = as_u32(nibble_index);
    let byte = byte_at(input, byte_offset + (idx / 2) as Field);
    if idx % 2 == 0 {
        (byte / 16) as Field
    } else {
        (byte % 16) as Field
    }
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

pub fn assert_canonical_rlp_string_item(
    input: [u8; 1024],
    layout: [Field; 4],
    node_len: Field,
) {
    assert_layout_range(layout, node_len);

    let encoded_offset = as_u32(layout[0]);
    let encoded_len = as_u32(layout[1]);
    let payload_offset = as_u32(layout[2]);
    let payload_len = as_u32(layout[3]);
    let prefix = byte_at(input, layout[0]) as u32;

    if payload_len == 0 {
        assert(encoded_len == 1);
        assert(prefix == 0x80);
        assert(payload_offset == encoded_offset + 1);
    } else if encoded_len == 1 {
        assert(payload_len == 1);
        assert(payload_offset == encoded_offset);
        assert(prefix > 0);
        assert(prefix < 0x80);
    } else if payload_len <= 55 {
        assert(encoded_len == payload_len + 1);
        assert(prefix == 0x80 + payload_len);
        assert(payload_offset == encoded_offset + 1);

        let first_payload_byte = byte_at(input, layout[2]);
        assert(first_payload_byte != 0);
        if payload_len == 1 {
            assert(first_payload_byte >= 0x80);
        }
    } else if payload_len <= 255 {
        assert(encoded_len == payload_len + 2);
        assert(prefix == 0xB8);
        assert(byte_at(input, layout[0] + 1) as u32 == payload_len);
        assert(byte_at(input, layout[0] + 1) != 0);
        assert(payload_offset == encoded_offset + 2);
    } else {
        assert(encoded_len == payload_len + 3);
        assert(prefix == 0xB9);
        let len_hi = byte_at(input, layout[0] + 1) as u32;
        let len_lo = byte_at(input, layout[0] + 2) as u32;
        assert(len_hi != 0);
        assert(len_hi * 256 + len_lo == payload_len);
        assert(payload_offset == encoded_offset + 3);
    }
}

pub fn assert_canonical_rlp_list_item(
    input: [u8; 1024],
    layout: [Field; 4],
    node_len: Field,
) {
    assert_layout_range(layout, node_len);

    let encoded_offset = as_u32(layout[0]);
    let encoded_len = as_u32(layout[1]);
    let payload_offset = as_u32(layout[2]);
    let payload_len = as_u32(layout[3]);
    let prefix = byte_at(input, layout[0]) as u32;

    if payload_len <= 55 {
        assert(encoded_len == payload_len + 1);
        assert(prefix == 0xC0 + payload_len);
        assert(payload_offset == encoded_offset + 1);
    } else if payload_len <= 255 {
        assert(encoded_len == payload_len + 2);
        assert(prefix == 0xF8);
        assert(byte_at(input, layout[0] + 1) as u32 == payload_len);
        assert(byte_at(input, layout[0] + 1) != 0);
        assert(payload_offset == encoded_offset + 2);
    } else {
        assert(encoded_len == payload_len + 3);
        assert(prefix == 0xF9);
        let len_hi = byte_at(input, layout[0] + 1) as u32;
        let len_lo = byte_at(input, layout[0] + 2) as u32;
        assert(len_hi != 0);
        assert(len_hi * 256 + len_lo == payload_len);
        assert(payload_offset == encoded_offset + 3);
    }
}

pub fn assert_canonical_compact_path_item(
    input: [u8; 1024],
    layout: [Field; 4],
    node_len: Field,
    leaf_path_nibbles: [Field; 64],
    leaf_path_len: Field,
) {
    assert_canonical_rlp_string_item(input, layout, node_len);

    let payload_offset = layout[2];
    let payload_len = as_u32(layout[3]);
    let leaf_path_len_u32 = as_u32(leaf_path_len);
    let first_payload_byte = byte_at(input, payload_offset);
    let flag_nibble = (first_payload_byte / 16) as u32;

    if flag_nibble == 2 {
        assert(first_payload_byte % 16 == 0);
    } else {
        assert(flag_nibble == 3);
    }

    let path_start = if flag_nibble == 3 { 1 } else { 2 };
    assert(path_start + leaf_path_len_u32 == payload_len * 2);

    for i in 0..64 {
        if i < leaf_path_len_u32 {
            let nibble_index = path_start + i;
            assert(
                leaf_path_nibbles[i]
                    == nibble_at(input, payload_offset, nibble_index as Field),
            );
            crate::types::assert_nibble(leaf_path_nibbles[i]);
        } else {
            assert(leaf_path_nibbles[i] == 0);
        }
    }
}

pub fn assert_canonical_account_scalar_item(
    input: [u8; 1024],
    layout: [Field; 4],
    node_len: Field,
) {
    assert_canonical_rlp_string_item(input, layout, node_len);

    let encoded_len = as_u32(layout[1]);
    let payload_len = as_u32(layout[3]);
    let payload_offset = as_u32(layout[2]);

    assert(payload_len <= 32);
    if payload_len == 0 {
        assert(encoded_len == 1);
        assert(byte_at(input, layout[0]) == 0x80);
    } else if encoded_len == 1 {
        let value = byte_at(input, layout[0]);
        assert(value > 0);
        assert(value < 0x80);
    } else {
        let first_payload_byte = byte_at(input, layout[2]);
        assert(first_payload_byte != 0);
        if payload_len == 1 {
            assert(first_payload_byte >= 0x80);
        }
        assert(payload_offset == as_u32(layout[0]) + 1);
    }
}

pub fn assert_canonical_bytes32_item(
    input: [u8; 1024],
    layout: [Field; 4],
    node_len: Field,
) {
    assert_canonical_rlp_string_item(input, layout, node_len);
    assert(as_u32(layout[3]) == 32);
    assert(as_u32(layout[1]) == 33);
    assert(byte_at(input, layout[0]) == 0xA0);
    assert(as_u32(layout[2]) == as_u32(layout[0]) + 1);
}

pub fn assert_canonical_terminal_leaf_and_account_rlp(
    leaf_node: [u8; 1024],
    leaf_node_len: Field,
    leaf_outer_list: [Field; 4],
    leaf_compact_path: [Field; 4],
    leaf_account_value: [Field; 4],
    account_inner_list: [Field; 4],
    account_nonce: [Field; 4],
    account_balance: [Field; 4],
    account_storage_root: [Field; 4],
    account_code_hash: [Field; 4],
    leaf_path_nibbles: [Field; 64],
    leaf_path_len: Field,
) {
    assert_canonical_rlp_list_item(leaf_node, leaf_outer_list, leaf_node_len);
    assert(leaf_outer_list[0] == 0);
    assert(leaf_outer_list[1] == leaf_node_len);

    assert_canonical_compact_path_item(
        leaf_node,
        leaf_compact_path,
        leaf_node_len,
        leaf_path_nibbles,
        leaf_path_len,
    );
    assert_canonical_rlp_string_item(leaf_node, leaf_account_value, leaf_node_len);
    assert(leaf_compact_path[0] == leaf_outer_list[2]);
    assert(leaf_account_value[0] == leaf_compact_path[0] + leaf_compact_path[1]);
    assert(leaf_account_value[0] + leaf_account_value[1] == leaf_outer_list[2] + leaf_outer_list[3]);

    assert_canonical_rlp_list_item(leaf_node, account_inner_list, leaf_node_len);
    assert(account_inner_list[0] == leaf_account_value[2]);
    assert(account_inner_list[1] == leaf_account_value[3]);
    assert(account_inner_list[0] + account_inner_list[1] == leaf_account_value[2] + leaf_account_value[3]);

    assert_canonical_account_scalar_item(leaf_node, account_nonce, leaf_node_len);
    assert_canonical_account_scalar_item(leaf_node, account_balance, leaf_node_len);
    assert_canonical_bytes32_item(leaf_node, account_storage_root, leaf_node_len);
    assert_canonical_bytes32_item(leaf_node, account_code_hash, leaf_node_len);

    assert(account_nonce[0] == account_inner_list[2]);
    assert(account_balance[0] == account_nonce[0] + account_nonce[1]);
    assert(account_storage_root[0] == account_balance[0] + account_balance[1]);
    assert(account_code_hash[0] == account_storage_root[0] + account_storage_root[1]);
    assert(account_code_hash[0] + account_code_hash[1] == account_inner_list[2] + account_inner_list[3]);

    assert(account_storage_root[3] == 32);
    assert(account_code_hash[3] == 32);
    assert(account_inner_list[0] == leaf_account_value[2]);
    assert(account_inner_list[1] == leaf_account_value[3]);
}

fn valid_leaf_node() -> [u8; 1024] {
    let mut input = [0; 1024];
    input[0] = 248;
    input[1] = 75;
    input[2] = 130;
    input[3] = 32;
    input[4] = 171;
    input[5] = 184;
    input[6] = 70;
    input[7] = 248;
    input[8] = 68;
    input[9] = 128;
    input[10] = 128;
    input[11] = 160;
    for i in 0..32 {
        input[12 + i] = (i + 1) as u8;
        input[45 + i] = (0x80 + i) as u8;
    }
    input[44] = 160;
    input
}

fn distinct_nonce_balance_leaf_node() -> [u8; 1024] {
    let mut input = [0; 1024];
    input[0] = 248;
    input[1] = 76;
    input[2] = 130;
    input[3] = 32;
    input[4] = 171;
    input[5] = 184;
    input[6] = 71;
    input[7] = 248;
    input[8] = 69;
    input[9] = 128;
    input[10] = 129;
    input[11] = 128;
    input[12] = 160;
    for i in 0..32 {
        input[13 + i] = (i + 1) as u8;
        input[46 + i] = (0x80 + i) as u8;
    }
    input[45] = 160;
    input
}

fn valid_leaf_path_nibbles() -> [Field; 64] {
    let mut path = [0; 64];
    path[0] = 10;
    path[1] = 11;
    path
}

fn valid_outer_layout() -> [Field; 4] {
    [0, 77, 2, 75]
}

fn distinct_outer_layout() -> [Field; 4] {
    [0, 78, 2, 76]
}

fn valid_compact_path_layout() -> [Field; 4] {
    [2, 3, 3, 2]
}

fn valid_account_value_layout() -> [Field; 4] {
    [5, 72, 7, 70]
}

fn distinct_account_value_layout() -> [Field; 4] {
    [5, 73, 7, 71]
}

fn valid_account_inner_layout() -> [Field; 4] {
    [7, 70, 9, 68]
}

fn distinct_account_inner_layout() -> [Field; 4] {
    [7, 71, 9, 69]
}

fn valid_nonce_layout() -> [Field; 4] {
    [9, 1, 10, 0]
}

fn valid_balance_layout() -> [Field; 4] {
    [10, 1, 11, 0]
}

fn distinct_balance_layout() -> [Field; 4] {
    [10, 2, 11, 1]
}

fn valid_storage_root_layout() -> [Field; 4] {
    [11, 33, 12, 32]
}

fn distinct_storage_root_layout() -> [Field; 4] {
    [12, 33, 13, 32]
}

fn valid_code_hash_layout() -> [Field; 4] {
    [44, 33, 45, 32]
}

fn distinct_code_hash_layout() -> [Field; 4] {
    [45, 33, 46, 32]
}

#[test]
fn test_valid_canonical_terminal_leaf_account_rlp() {
    let leaf = valid_leaf_node();
    assert_canonical_terminal_leaf_and_account_rlp(
        leaf,
        77,
        valid_outer_layout(),
        valid_compact_path_layout(),
        valid_account_value_layout(),
        valid_account_inner_layout(),
        valid_nonce_layout(),
        valid_balance_layout(),
        valid_storage_root_layout(),
        valid_code_hash_layout(),
        valid_leaf_path_nibbles(),
        2,
    );
}

#[test]
fn test_long_string_item_accepts_two_byte_length_of_length() {
    let mut input = [0; 1024];
    input[0] = 185;
    input[1] = 1;
    input[2] = 44;
    let layout: [Field; 4] = [0, 303, 3, 300];
    assert_canonical_rlp_string_item(input, layout, 303);
}

#[test]
fn test_long_list_item_accepts_two_byte_length_of_length() {
    let mut input = [0; 1024];
    input[0] = 249;
    input[1] = 1;
    input[2] = 44;
    let layout: [Field; 4] = [0, 303, 3, 300];
    assert_canonical_rlp_list_item(input, layout, 303);
}

#[test]
fn test_canonical_single_byte_scalar_item() {
    let mut input = [0; 1024];
    input[0] = 1;
    assert_canonical_account_scalar_item(input, [0, 1, 0, 1], 1);
}

#[test(should_fail)]
fn test_rejects_wrong_outer_item_count() {
    let mut input = valid_leaf_node();
    input[1] = 76;
    input[77] = 128;
    assert_canonical_terminal_leaf_and_account_rlp(
        input,
        78,
        [0, 78, 2, 76],
        valid_compact_path_layout(),
        [5, 73, 7, 71],
        valid_account_inner_layout(),
        valid_nonce_layout(),
        valid_balance_layout(),
        valid_storage_root_layout(),
        valid_code_hash_layout(),
        valid_leaf_path_nibbles(),
        2,
    );
}

#[test(should_fail)]
fn test_rejects_bad_compact_path_flags() {
    let mut input = valid_leaf_node();
    input[2] = 3;
    input[3] = 0;
    input[4] = 171;
    assert_canonical_compact_path_item(
        input,
        valid_compact_path_layout(),
        77,
        valid_leaf_path_nibbles(),
        2,
    );
}

#[test(should_fail)]
fn test_rejects_nonce_and_balance_swapped() {
    let leaf = distinct_nonce_balance_leaf_node();
    assert_canonical_terminal_leaf_and_account_rlp(
        leaf,
        78,
        distinct_outer_layout(),
        valid_compact_path_layout(),
        distinct_account_value_layout(),
        distinct_account_inner_layout(),
        distinct_balance_layout(),
        valid_nonce_layout(),
        distinct_storage_root_layout(),
        distinct_code_hash_layout(),
        valid_leaf_path_nibbles(),
        2,
    );
}

#[test(should_fail)]
fn test_rejects_zero_nonce_with_trailing_bytes() {
    let mut input = valid_leaf_node();
    input[9] = 129;
    input[10] = 0;
    assert_canonical_account_scalar_item(input, valid_nonce_layout(), 77);
}

#[test(should_fail)]
fn test_rejects_leading_zero_balance() {
    let mut input = valid_leaf_node();
    input[10] = 129;
    input[11] = 0;
    assert_canonical_account_scalar_item(
        input,
        [10, 2, 11, 1],
        77,
    );
}

#[test(should_fail)]
fn test_rejects_noncanonical_single_byte_scalar() {
    let mut input = [0; 1024];
    input[0] = 0;
    assert_canonical_account_scalar_item(input, [0, 1, 0, 1], 1);
}

#[test(should_fail)]
fn test_rejects_storage_root_length_31() {
    let mut input = valid_leaf_node();
    input[11] = 159;
    assert_canonical_bytes32_item(input, valid_storage_root_layout(), 77);
}

#[test(should_fail)]
fn test_rejects_code_hash_length_33() {
    let mut input = valid_leaf_node();
    input[44] = 161;
    assert_canonical_bytes32_item(input, valid_code_hash_layout(), 77);
}

#[test(should_fail)]
fn test_rejects_outer_length_mismatch() {
    let leaf = valid_leaf_node();
    assert_canonical_terminal_leaf_and_account_rlp(
        leaf,
        78,
        [0, 77, 2, 75],
        valid_compact_path_layout(),
        valid_account_value_layout(),
        valid_account_inner_layout(),
        valid_nonce_layout(),
        valid_balance_layout(),
        valid_storage_root_layout(),
        valid_code_hash_layout(),
        valid_leaf_path_nibbles(),
        2,
    );
}
