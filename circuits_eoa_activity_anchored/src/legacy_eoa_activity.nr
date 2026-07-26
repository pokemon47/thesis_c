pub fn statement_tag() -> Field {
    4
}

fn prove_one(
    state_root: [u8; 32],
    account_address: [u8; 20],
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
    let address_hash = crate::hash_keccak::hash_address(account_address);
    crate::mpt_simplified::assert_account_path(address_hash, path_nibbles);

    assert(node_kinds[0] == 0);
    assert(node_kinds[1] == 0);
    assert(node_kinds[2] == 0);
    assert(node_kinds[3] == 2);

    let node_hash_0 = crate::hash_keccak::hash_node(node_rlp_bytes[0], node_rlp_lens[0]);
    let node_hash_1 = crate::hash_keccak::hash_node(node_rlp_bytes[1], node_rlp_lens[1]);
    let node_hash_2 = crate::hash_keccak::hash_node(node_rlp_bytes[2], node_rlp_lens[2]);
    let node_hash_3 = crate::hash_keccak::hash_node(node_rlp_bytes[3], node_rlp_lens[3]);

    assert(node_hash_0 == state_root);

    assert(branch_child_indices[0] == path_nibbles[0]);
    assert(branch_child_indices[1] == path_nibbles[1]);
    assert(branch_child_indices[2] == path_nibbles[2]);

    let selected_child_0 = crate::mpt_simplified::select_branch_child_hash(
        branch_children[0],
        branch_child_indices[0],
    );
    let selected_child_1 = crate::mpt_simplified::select_branch_child_hash(
        branch_children[1],
        branch_child_indices[1],
    );
    let selected_child_2 = crate::mpt_simplified::select_branch_child_hash(
        branch_children[2],
        branch_child_indices[2],
    );

    assert(selected_child_0 == branch_child_hashes[0]);
    assert(selected_child_1 == branch_child_hashes[1]);
    assert(selected_child_2 == branch_child_hashes[2]);

    assert(node_hash_1 == selected_child_0);
    assert(node_hash_2 == selected_child_1);
    assert(node_hash_3 == selected_child_2);

    crate::mpt_simplified::assert_leaf_path_suffix(
        path_nibbles,
        3,
        leaf_path_nibbles,
        leaf_path_len,
    );

    crate::rlp_balance::assert_eoa_account_layout(
        node_rlp_bytes[3],
        node_rlp_lens[3],
        leaf_outer_list_layout,
        leaf_compact_path_layout,
        leaf_account_value_layout,
        account_inner_list_layout,
        account_nonce_layout,
        account_balance_layout,
        account_storage_root_layout,
        account_code_hash_layout,
    );
}

pub fn prove(
    hash_variant_id: Field,
    account_address: [u8; 20],
    state_root_1: [u8; 32],
    state_root_2: [u8; 32],
    node_rlp_bytes_1: [[u8; 544]; 4],
    node_rlp_lens_1: [Field; 4],
    node_kinds_1: [Field; 4],
    branch_child_indices_1: [Field; 3],
    branch_child_hashes_1: [[u8; 32]; 3],
    branch_children_1: [[[u8; 32]; 16]; 3],
    path_nibbles_1: [Field; 64],
    leaf_path_nibbles_1: [Field; 64],
    leaf_path_len_1: Field,
    leaf_outer_list_layout_1: [Field; 4],
    leaf_compact_path_layout_1: [Field; 4],
    leaf_account_value_layout_1: [Field; 4],
    account_inner_list_layout_1: [Field; 4],
    account_nonce_layout_1: [Field; 4],
    account_balance_layout_1: [Field; 4],
    account_storage_root_layout_1: [Field; 4],
    account_code_hash_layout_1: [Field; 4],
    node_rlp_bytes_2: [[u8; 544]; 4],
    node_rlp_lens_2: [Field; 4],
    node_kinds_2: [Field; 4],
    branch_child_indices_2: [Field; 3],
    branch_child_hashes_2: [[u8; 32]; 3],
    branch_children_2: [[[u8; 32]; 16]; 3],
    path_nibbles_2: [Field; 64],
    leaf_path_nibbles_2: [Field; 64],
    leaf_path_len_2: Field,
    leaf_outer_list_layout_2: [Field; 4],
    leaf_compact_path_layout_2: [Field; 4],
    leaf_account_value_layout_2: [Field; 4],
    account_inner_list_layout_2: [Field; 4],
    account_nonce_layout_2: [Field; 4],
    account_balance_layout_2: [Field; 4],
    account_storage_root_layout_2: [Field; 4],
    account_code_hash_layout_2: [Field; 4],
) {
    assert(hash_variant_id == 1);

    prove_one(
        state_root_1,
        account_address,
        node_rlp_bytes_1,
        node_rlp_lens_1,
        node_kinds_1,
        branch_child_indices_1,
        branch_child_hashes_1,
        branch_children_1,
        path_nibbles_1,
        leaf_path_nibbles_1,
        leaf_path_len_1,
        leaf_outer_list_layout_1,
        leaf_compact_path_layout_1,
        leaf_account_value_layout_1,
        account_inner_list_layout_1,
        account_nonce_layout_1,
        account_balance_layout_1,
        account_storage_root_layout_1,
        account_code_hash_layout_1,
    );
    prove_one(
        state_root_2,
        account_address,
        node_rlp_bytes_2,
        node_rlp_lens_2,
        node_kinds_2,
        branch_child_indices_2,
        branch_child_hashes_2,
        branch_children_2,
        path_nibbles_2,
        leaf_path_nibbles_2,
        leaf_path_len_2,
        leaf_outer_list_layout_2,
        leaf_compact_path_layout_2,
        leaf_account_value_layout_2,
        account_inner_list_layout_2,
        account_nonce_layout_2,
        account_balance_layout_2,
        account_storage_root_layout_2,
        account_code_hash_layout_2,
    );

    crate::rlp_balance::assert_nonce_encoding_differs(
        node_rlp_bytes_1[3],
        account_nonce_layout_1,
        node_rlp_bytes_2[3],
        account_nonce_layout_2,
    );
}
