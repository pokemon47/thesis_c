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

fn nibble_from_bytes32(input: [u8; 32], index: u32) -> Field {
    let byte = input[index / 2];
    if index % 2 == 0 {
        (byte / 16) as Field
    } else {
        (byte % 16) as Field
    }
}

pub fn extract_storage_root(
    leaf_node: [u8; 544],
    storage_root_layout: [Field; 4],
) -> [u8; 32] {
    let offset = as_u32(storage_root_layout[2]);
    let length = as_u32(storage_root_layout[3]);
    assert(length == 32);

    let mut output = [0; 32];
    for i in 0..32 {
        output[i] = byte_at(leaf_node, (offset + i) as Field);
    }
    output
}

pub fn assert_one_node_storage_leaf(
    storage_node: [u8; 544],
    storage_node_len: Field,
    authenticated_storage_root: [u8; 32],
    authenticated_storage_root_field: Field,
    public_storage_slot: [u8; 32],
    private_storage_key_hash: [u8; 32],
    private_storage_key_field: Field,
    private_storage_leaf_hash_field: Field,
    private_storage_path_nibbles: [Field; 64],
    private_storage_path_len: Field,
    storage_outer_list_layout: [Field; 4],
    storage_compact_path_layout: [Field; 4],
    storage_value_item_layout: [Field; 4],
    storage_value_active_bytes: [u8; 32],
    storage_value_active_len: Field,
    storage_value_padded: [u8; 32],
    public_expected_storage_value: [u8; 32],
) {
    let node_len = as_u32(storage_node_len);
    assert(node_len > 0);
    assert(node_len <= 544);

    assert(crate::types::canonical_bytes32_to_field(authenticated_storage_root) == authenticated_storage_root_field);
    let derived_leaf_hash = crate::hash_poseidon2::hash_node_field(storage_node, storage_node_len);
    assert(derived_leaf_hash == authenticated_storage_root_field);
    assert(private_storage_leaf_hash_field == derived_leaf_hash);

    let derived_key_field = crate::hash_poseidon2::hash_storage_slot_field(public_storage_slot);
    assert(private_storage_key_field == derived_key_field);
    assert(crate::types::canonical_bytes32_to_field(private_storage_key_hash) == derived_key_field);
    assert(private_storage_path_len == 64);
    let path_len = as_u32(private_storage_path_len);
    assert(path_len == 64);
    for i in 0..64 {
        crate::types::assert_nibble(private_storage_path_nibbles[i]);
        assert(private_storage_path_nibbles[i] == nibble_from_bytes32(private_storage_key_hash, i));
    }

    crate::types::rlp_account::assert_canonical_rlp_list_item(
        storage_node,
        storage_outer_list_layout,
        storage_node_len,
    );
    assert(storage_outer_list_layout[0] == 0);
    assert(storage_outer_list_layout[1] == storage_node_len);

    crate::types::rlp_account::assert_canonical_compact_path_item(
        storage_node,
        storage_compact_path_layout,
        storage_node_len,
        private_storage_path_nibbles,
        private_storage_path_len,
    );
    assert(storage_compact_path_layout[0] == storage_outer_list_layout[2]);

    crate::types::rlp_account::assert_canonical_account_scalar_item(
        storage_node,
        storage_value_item_layout,
        storage_node_len,
    );
    assert(storage_value_item_layout[0] == storage_compact_path_layout[0] + storage_compact_path_layout[1]);
    assert(storage_value_item_layout[0] + storage_value_item_layout[1] == storage_outer_list_layout[2] + storage_outer_list_layout[3]);

    let active_len = as_u32(storage_value_active_len);
    assert(storage_value_active_len == storage_value_item_layout[3]);
    assert(active_len > 0);
    assert(active_len <= 32);
    for i in 0..32 {
        if i < active_len {
            assert(storage_value_active_bytes[i] == byte_at(storage_node, storage_value_item_layout[2] + i as Field));
        } else {
            assert(storage_value_active_bytes[i] == 0);
        }
    }

    let padding_len = 32 - active_len;
    for i in 0..32 {
        if i < padding_len {
            assert(storage_value_padded[i] == 0);
        } else {
            assert(storage_value_padded[i] == storage_value_active_bytes[i - padding_len]);
        }
        assert(storage_value_padded[i] == public_expected_storage_value[i]);
    }
}

#[test]
fn test_retained_poseidon2_storage_leaf_value_42() {
    let key_hash: [u8; 32] = [
        11, 99, 165, 55, 135, 2, 26, 74, 150, 42, 69, 44, 41, 33, 179, 102,
        58, 255, 31, 253, 141, 85, 16, 84, 15, 142, 101, 158, 120, 41, 86, 241,
    ];
    let mut node = [0; 544];
    node[0] = 227;
    node[1] = 161;
    node[2] = 32;
    for i in 0..32 {
        node[3 + i] = key_hash[i];
    }
    node[35] = 42;

    let mut path = [0; 64];
    for i in 0..64 {
        path[i] = nibble_from_bytes32(key_hash, i);
    }
    let mut active = [0; 32];
    active[0] = 42;
    let mut padded = [0; 32];
    padded[31] = 42;
    assert_one_node_storage_leaf(
        node,
        36,
        [20, 254, 194, 196, 244, 137, 218, 67, 168, 4, 229, 14, 18, 107, 188, 143,
         26, 73, 101, 98, 71, 199, 49, 121, 195, 186, 5, 153, 196, 108, 194, 133],
        9496380374812769953476289295759068649277773052809521082516342337816851432069,
        [0; 32],
        key_hash,
        5151499478991301833156025595048985053689893395646836724335623777508747990769,
        9496380374812769953476289295759068649277773052809521082516342337816851432069,
        path,
        64,
        [0, 36, 1, 35],
        [1, 34, 2, 33],
        [35, 1, 35, 1],
        active,
        1,
        padded,
        padded,
    );
}
