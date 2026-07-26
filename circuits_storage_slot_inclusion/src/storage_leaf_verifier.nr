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
    public_storage_slot: [u8; 32],
    private_storage_key_hash: [u8; 32],
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

    assert(crate::hash_keccak::hash_node(storage_node, storage_node_len) == authenticated_storage_root);

    let derived_key_hash = crate::hash_keccak::hash_storage_slot(public_storage_slot);
    assert(private_storage_key_hash == derived_key_hash);
    assert(private_storage_path_len == 64);
    let path_len = as_u32(private_storage_path_len);
    assert(path_len == 64);
    for i in 0..64 {
        crate::types::assert_nibble(private_storage_path_nibbles[i]);
        assert(private_storage_path_nibbles[i] == nibble_from_bytes32(derived_key_hash, i));
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

fn synthetic_storage_fixture() -> ([u8; 544], [Field; 64], [Field; 4], [Field; 4], [Field; 4], [u8; 32]) {
    let slot = [0; 32];
    let key_hash = crate::hash_keccak::hash_storage_slot(slot);
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
    (
        node,
        path,
        [0, 36, 1, 35],
        [1, 34, 2, 33],
        [35, 1, 35, 1],
        crate::hash_keccak::hash_node(node, 36),
    )
}

#[test]
fn test_one_node_storage_leaf_valid() {
    let (node, path, outer, compact, value, root) = synthetic_storage_fixture();
    let mut active = [0; 32];
    active[0] = 42;
    let mut padded = [0; 32];
    padded[31] = 42;
    assert_one_node_storage_leaf(
        node,
        36,
        root,
        [0; 32],
        crate::hash_keccak::hash_storage_slot([0; 32]),
        path,
        64,
        outer,
        compact,
        value,
        active,
        1,
        padded,
        padded,
    );
}

#[test(should_fail)]
fn test_one_node_storage_leaf_wrong_public_value_fails() {
    let (node, path, outer, compact, value, root) = synthetic_storage_fixture();
    let mut active = [0; 32];
    active[0] = 42;
    let mut padded = [0; 32];
    padded[31] = 42;
    let mut wrong = padded;
    wrong[31] = 43;
    assert_one_node_storage_leaf(
        node,
        36,
        root,
        [0; 32],
        crate::hash_keccak::hash_storage_slot([0; 32]),
        path,
        64,
        outer,
        compact,
        value,
        active,
        1,
        padded,
        wrong,
    );
}

#[test(should_fail)]
fn test_one_node_storage_leaf_wrong_path_fails() {
    let (node, mut path, outer, compact, value, root) = synthetic_storage_fixture();
    if path[0] == 0 {
        path[0] = 1;
    } else {
        path[0] = 0;
    }
    let mut active = [0; 32];
    active[0] = 42;
    let mut padded = [0; 32];
    padded[31] = 42;
    assert_one_node_storage_leaf(
        node,
        36,
        root,
        [0; 32],
        crate::hash_keccak::hash_storage_slot([0; 32]),
        path,
        64,
        outer,
        compact,
        value,
        active,
        1,
        padded,
        padded,
    );
}
