pub fn nibble_from_bytes32(bytes32: [u8; 32], index: Field) -> Field {
    let i = index as u32;

    // Ensure the Field-to-u32 conversion did not truncate the value.
    assert(index == i as Field);
    assert(i < 64);

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
        assert(
            path_nibbles[i]
                == nibble_from_bytes32(address_hash, i as Field),
        );

        crate::types::assert_nibble(path_nibbles[i]);
    }
}

pub fn select_branch_child_hash(
    branch_children: [[u8; 32]; 16],
    child_index: Field,
) -> [u8; 32] {
    crate::types::assert_nibble(child_index);

    let child_index_u32 = child_index as u32;

    // Prevent an invalid or truncated Field value from being used as an index.
    assert(child_index == child_index_u32 as Field);
    assert(child_index_u32 < 16);

    branch_children[child_index_u32]
}

pub fn select_branch_child_field(
    branch_children: [Field; 16],
    child_index: Field,
) -> Field {
    crate::types::assert_nibble(child_index);

    let child_index_u32 = child_index as u32;

    // Prevent an invalid or truncated Field value from being used as an index.
    assert(child_index == child_index_u32 as Field);
    assert(child_index_u32 < 16);

    branch_children[child_index_u32]
}

pub fn assert_leaf_path_suffix(
    path_nibbles: [Field; 64],
    branch_depth: Field,
    leaf_path_nibbles: [Field; 64],
    leaf_path_len: Field,
) {
    // Noir does not support ordering comparisons directly on Field values.
    // Convert the lengths to u32, then constrain the conversions so values
    // cannot be silently truncated.
    let branch_depth_u32 = branch_depth as u32;
    let leaf_path_len_u32 = leaf_path_len as u32;

    assert(branch_depth == branch_depth_u32 as Field);
    assert(leaf_path_len == leaf_path_len_u32 as Field);

    assert(branch_depth_u32 <= 64);
    assert(leaf_path_len_u32 <= 64);
    assert(branch_depth_u32 + leaf_path_len_u32 <= 64);

    for i in 0..64 {
        if i < leaf_path_len_u32 {
            let source_idx = branch_depth_u32 + i;

            assert(
                leaf_path_nibbles[i]
                    == path_nibbles[source_idx],
            );

            crate::types::assert_nibble(leaf_path_nibbles[i]);
        } else {
            assert(leaf_path_nibbles[i] == 0);
        }
    }
}
