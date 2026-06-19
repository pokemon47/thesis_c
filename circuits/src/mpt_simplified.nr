pub fn nibble_from_bytes32(bytes32: [u8; 32], index: Field) -> Field {
    let i = index as u32;
    let byte_index = i / 2;
    let byte_value = bytes32[byte_index];
    if i % 2 == 0 {
        (byte_value / 16) as Field
    } else {
        (byte_value % 16) as Field
    }
}

pub fn assert_account_path(
    address_hash: [u8; 32],
    path_nibbles: [Field; 64],
) {
    for i in 0..64 {
        assert(path_nibbles[i] == nibble_from_bytes32(address_hash, i as Field));
        crate::types::assert_nibble(path_nibbles[i]);
    }
}

pub fn select_branch_child_hash(
    branch_children: [[u8; 32]; 16],
    child_index: Field,
) -> [u8; 32] {
    crate::types::assert_nibble(child_index);
    branch_children[child_index as u32]
}

pub fn assert_leaf_path_suffix(
    path_nibbles: [Field; 64],
    branch_depth: Field,
    leaf_path_nibbles: [Field; 64],
    leaf_path_len: Field,
) {
    for i in 0..64 {
        if (i as Field) < leaf_path_len {
            let source_idx = branch_depth + i as Field;
            assert(leaf_path_nibbles[i] == path_nibbles[source_idx as u32]);
            crate::types::assert_nibble(leaf_path_nibbles[i]);
        } else {
            assert(leaf_path_nibbles[i] == 0);
        }
    }
}
