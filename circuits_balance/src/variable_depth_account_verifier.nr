// Foundation-only variable active-depth account verifier.
// Supported language: branch^(depth - 1) -> terminal leaf, 2 <= depth <= 4.
// This module is not wired into a statement entrypoint in Task 1.

pub struct AuthenticatedTerminal {
    pub terminal_node_bytes: [u8; 544],
    pub terminal_node_len: Field,
    pub account_value_payload_offset: Field,
    pub account_value_payload_len: Field,
}

pub fn assert_variable_depth_shape(
    depth: Field,
    node_rlp_bytes: [[u8; 544]; 4],
    node_rlp_lens: [Field; 4],
    node_kinds: [Field; 4],
    branch_child_indices: [Field; 3],
    branch_child_hashes: [[u8; 32]; 3],
    branch_children: [[[u8; 32]; 16]; 3],
    path_nibbles: [Field; 64],
    leaf_path_nibbles: [Field; 64],
    leaf_path_len: Field,
) {
    let depth_u32 = depth as u32;
    assert(depth == depth_u32 as Field);
    assert(depth_u32 >= 2);
    assert(depth_u32 <= 4);

    let leaf_path_len_u32 = leaf_path_len as u32;
    assert(leaf_path_len == leaf_path_len_u32 as Field);
    assert(leaf_path_len_u32 <= 64);
    assert(depth_u32 - 1 + leaf_path_len_u32 == 64);

    for i in 0..64 {
        crate::types::assert_nibble(path_nibbles[i]);
        if i < leaf_path_len_u32 {
            crate::types::assert_nibble(leaf_path_nibbles[i]);
        } else {
            assert(leaf_path_nibbles[i] == 0);
        }
    }

    for i in 0..4 {
        let node_len_u32 = node_rlp_lens[i] as u32;
        assert(node_rlp_lens[i] == node_len_u32 as Field);
        assert(node_len_u32 <= 544);

        if i < depth_u32 {
            assert(node_len_u32 > 0);
            if i + 1 == depth_u32 {
                assert(node_kinds[i] == 2);
            } else {
                assert(node_kinds[i] == 0);
            }
            for j in 0..544 {
                if j >= node_len_u32 {
                    assert(node_rlp_bytes[i][j] == 0);
                }
            }
        } else {
            assert(node_rlp_lens[i] == 0);
            assert(node_kinds[i] == 0);
            for j in 0..544 {
                assert(node_rlp_bytes[i][j] == 0);
            }
        }
    }

    for i in 0..3 {
        if i < depth_u32 - 1 {
            crate::types::assert_nibble(branch_child_indices[i]);
        } else {
            assert(branch_child_indices[i] == 0);
            assert(branch_child_hashes[i] == [0; 32]);
            for slot in 0..16 {
                assert(branch_children[i][slot] == [0; 32]);
            }
        }
    }
}

pub fn authenticated_terminal(
    depth: Field,
    node_rlp_bytes: [[u8; 544]; 4],
    node_rlp_lens: [Field; 4],
    node_kinds: [Field; 4],
    branch_child_indices: [Field; 3],
    branch_child_hashes: [[u8; 32]; 3],
    branch_children: [[[u8; 32]; 16]; 3],
    path_nibbles: [Field; 64],
    leaf_path_nibbles: [Field; 64],
    leaf_path_len: Field,
    account_value_payload_layout: [Field; 4],
) -> AuthenticatedTerminal {
    assert_variable_depth_shape(
        depth,
        node_rlp_bytes,
        node_rlp_lens,
        node_kinds,
        branch_child_indices,
        branch_child_hashes,
        branch_children,
        path_nibbles,
        leaf_path_nibbles,
        leaf_path_len,
    );

    let depth_u32 = depth as u32;
    let terminal_index = depth_u32 - 1;
    let payload_end = (account_value_payload_layout[0] + account_value_payload_layout[1]) as u32;
    let terminal_len = node_rlp_lens[terminal_index] as u32;
    assert(account_value_payload_layout[0] + account_value_payload_layout[1] == payload_end as Field);
    assert(node_rlp_lens[terminal_index] == terminal_len as Field);
    assert(payload_end <= terminal_len);

    AuthenticatedTerminal {
        terminal_node_bytes: node_rlp_bytes[terminal_index],
        terminal_node_len: node_rlp_lens[terminal_index],
        account_value_payload_offset: account_value_payload_layout[0],
        account_value_payload_len: account_value_payload_layout[1],
    }
}

pub fn assert_variable_depth_keccak(
    state_root: [u8; 32],
    account_address: [u8; 20],
    depth: Field,
    node_rlp_bytes: [[u8; 544]; 4],
    node_rlp_lens: [Field; 4],
    node_kinds: [Field; 4],
    branch_child_indices: [Field; 3],
    branch_child_hashes: [[u8; 32]; 3],
    branch_children: [[[u8; 32]; 16]; 3],
    path_nibbles: [Field; 64],
    leaf_path_nibbles: [Field; 64],
    leaf_path_len: Field,
    leaf_outer_list_layout: [Field; 4],
    leaf_compact_path_layout: [Field; 4],
    leaf_account_value_layout: [Field; 4],
    account_inner_list_layout: [Field; 4],
    account_nonce_layout: [Field; 4],
    account_balance_layout: [Field; 4],
    account_storage_root_layout: [Field; 4],
    account_code_hash_layout: [Field; 4],
) {
    assert_variable_depth_shape(
        depth,
        node_rlp_bytes,
        node_rlp_lens,
        node_kinds,
        branch_child_indices,
        branch_child_hashes,
        branch_children,
        path_nibbles,
        leaf_path_nibbles,
        leaf_path_len,
    );

    let address_hash = crate::hash_keccak::hash_address(account_address);
    crate::mpt_simplified::assert_account_path(address_hash, path_nibbles);

    let node_hash_0 = crate::hash_keccak::hash_node(node_rlp_bytes[0], node_rlp_lens[0]);
    let node_hash_1 = crate::hash_keccak::hash_node(node_rlp_bytes[1], node_rlp_lens[1]);
    let node_hash_2 = crate::hash_keccak::hash_node(node_rlp_bytes[2], node_rlp_lens[2]);
    let node_hash_3 = crate::hash_keccak::hash_node(node_rlp_bytes[3], node_rlp_lens[3]);
    assert(node_hash_0 == state_root);

    let depth_u32 = depth as u32;
    if depth_u32 >= 2 {
        assert(branch_child_indices[0] == path_nibbles[0]);
        assert(crate::mpt_simplified::select_branch_child_hash(branch_children[0], branch_child_indices[0]) == branch_child_hashes[0]);
        assert(node_hash_1 == branch_child_hashes[0]);
    }
    if depth_u32 >= 3 {
        assert(branch_child_indices[1] == path_nibbles[1]);
        assert(crate::mpt_simplified::select_branch_child_hash(branch_children[1], branch_child_indices[1]) == branch_child_hashes[1]);
        assert(node_hash_2 == branch_child_hashes[1]);
    }
    if depth_u32 >= 4 {
        assert(branch_child_indices[2] == path_nibbles[2]);
        assert(crate::mpt_simplified::select_branch_child_hash(branch_children[2], branch_child_indices[2]) == branch_child_hashes[2]);
        assert(node_hash_3 == branch_child_hashes[2]);
    }

    crate::mpt_simplified::assert_leaf_path_suffix(
        path_nibbles,
        (depth_u32 - 1) as Field,
        leaf_path_nibbles,
        leaf_path_len,
    );

    let terminal_index = depth_u32 - 1;
    crate::types::rlp_account::assert_canonical_terminal_leaf_and_account_rlp(
        node_rlp_bytes[terminal_index],
        node_rlp_lens[terminal_index],
        leaf_outer_list_layout,
        leaf_compact_path_layout,
        leaf_account_value_layout,
        account_inner_list_layout,
        account_nonce_layout,
        account_balance_layout,
        account_storage_root_layout,
        account_code_hash_layout,
        leaf_path_nibbles,
        leaf_path_len,
    );
}

#[test]
fn variable_depth_range_and_padding_are_constrained() {
    let bytes = [[0; 544]; 4];
    let lens = [1, 1, 1, 0];
    let kinds = [0, 0, 2, 0];
    let indices = [0, 0, 0];
    let hashes = [[0; 32]; 3];
    let children = [[[0; 32]; 16]; 3];
    let path = [0; 64];
    let leaf_path = [0; 64];
    assert_variable_depth_shape(3, bytes, lens, kinds, indices, hashes, children, path, leaf_path, 62);
}

#[test(should_fail)]
fn rejects_depth_one() {
    assert_variable_depth_shape(1, [[0; 544]; 4], [1, 0, 0, 0], [2, 0, 0, 0], [0, 0, 0], [[0; 32]; 3], [[[0; 32]; 16]; 3], [0; 64], [0; 64], 63);
}

#[test(should_fail)]
fn rejects_depth_five() {
    assert_variable_depth_shape(5, [[0; 544]; 4], [1, 1, 1, 1], [0, 0, 0, 2], [0, 0, 0], [[0; 32]; 3], [[[0; 32]; 16]; 3], [0; 64], [0; 64], 60);
}

#[test(should_fail)]
fn rejects_inactive_node_byte_mutation() {
    let mut bytes = [[0; 544]; 4];
    bytes[3][0] = 1;
    assert_variable_depth_shape(3, bytes, [1, 1, 1, 0], [0, 0, 2, 0], [0, 0, 0], [[0; 32]; 3], [[[0; 32]; 16]; 3], [0; 64], [0; 64], 62);
}

#[test(should_fail)]
fn rejects_inactive_metadata_mutation() {
    assert_variable_depth_shape(3, [[0; 544]; 4], [1, 1, 1, 0], [0, 0, 2, 2], [0, 0, 0], [[0; 32]; 3], [[[0; 32]; 16]; 3], [0; 64], [0; 64], 62);
}
