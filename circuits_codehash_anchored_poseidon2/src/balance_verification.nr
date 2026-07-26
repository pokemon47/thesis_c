pub fn statement_tag() -> Field {
    2
}

pub fn prove(
    state_root: [u8; 32],
    state_root_field: Field,
    account_address: [u8; 20],
    claimed_balance: [u8; 32],
    hash_variant_id: Field,
    node_rlp_bytes: [[u8; 544]; 4],
    node_rlp_lens: [Field; 4],
    node_kinds: [Field; 4],
    branch_child_indices: [Field; 3],
    branch_child_hashes: [[u8; 32]; 3],
    branch_child_hash_fields: [Field; 3],
    branch_children: [[[u8; 32]; 16]; 3],
    branch_children_fields: [[Field; 16]; 3],
    address_hash: [u8; 32],
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
    assert(hash_variant_id == 2);

    assert(crate::types::canonical_bytes32_to_field(state_root) == state_root_field);
    assert(
        crate::types::canonical_bytes32_to_field(address_hash)
            == crate::hash_poseidon2::hash_address_field(account_address),
    );
    crate::mpt_simplified::assert_account_path(address_hash, path_nibbles);

    for i in 0..3 {
        assert(
            crate::types::canonical_bytes32_to_field(branch_child_hashes[i])
                == branch_child_hash_fields[i],
        );
        for slot in 0..16 {
            assert(
                crate::types::canonical_bytes32_to_field(branch_children[i][slot])
                    == branch_children_fields[i][slot],
            );
        }
    }

    assert(node_kinds[0] == 0);
    assert(node_kinds[1] == 0);
    assert(node_kinds[2] == 0);
    assert(node_kinds[3] == 2);

    let node_hash_0 = crate::hash_poseidon2::hash_node_field(node_rlp_bytes[0], node_rlp_lens[0]);
    let node_hash_1 = crate::hash_poseidon2::hash_node_field(node_rlp_bytes[1], node_rlp_lens[1]);
    let node_hash_2 = crate::hash_poseidon2::hash_node_field(node_rlp_bytes[2], node_rlp_lens[2]);
    let node_hash_3 = crate::hash_poseidon2::hash_node_field(node_rlp_bytes[3], node_rlp_lens[3]);

    assert(node_hash_0 == state_root_field);

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
    let selected_child_field_0 = crate::mpt_simplified::select_branch_child_field(
        branch_children_fields[0],
        branch_child_indices[0],
    );
    let selected_child_field_1 = crate::mpt_simplified::select_branch_child_field(
        branch_children_fields[1],
        branch_child_indices[1],
    );
    let selected_child_field_2 = crate::mpt_simplified::select_branch_child_field(
        branch_children_fields[2],
        branch_child_indices[2],
    );

    assert(selected_child_0 == branch_child_hashes[0]);
    assert(selected_child_1 == branch_child_hashes[1]);
    assert(selected_child_2 == branch_child_hashes[2]);
    assert(selected_child_field_0 == branch_child_hash_fields[0]);
    assert(selected_child_field_1 == branch_child_hash_fields[1]);
    assert(selected_child_field_2 == branch_child_hash_fields[2]);

    assert(node_hash_1 == selected_child_field_0);
    assert(node_hash_2 == selected_child_field_1);
    assert(node_hash_3 == selected_child_field_2);

    crate::mpt_simplified::assert_leaf_path_suffix(
        path_nibbles,
        3,
        leaf_path_nibbles,
        leaf_path_len,
    );

    crate::rlp_balance::assert_account_balance_layout(
        node_rlp_bytes[3],
        node_rlp_lens[3],
        claimed_balance,
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
