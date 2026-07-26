pub fn statement_tag() -> Field {
    1
}

pub fn prove(
    state_root: [u8; 32],
    account_address: [u8; 20],
    hash_variant_id: Field,
    node_rlp_bytes: [[u8; 544]; 4],
    node_rlp_lens: [Field; 4],
    node_kinds: [Field; 4],
    branch_child_indices: [Field; 3],
    branch_child_hashes: [[u8; 32]; 3],
    branch_children: [[[u8; 32]; 16]; 3],
    path_nibbles: [Field; 64],
    leaf_path_nibbles: [Field; 64],
    leaf_path_len: Field,
    nonce: Field,
    balance: Field,
    storage_root: [u8; 32],
    code_hash: [u8; 32],
    leaf_value_commitment: Field,
) {
    // First-pass circuit supports keccak256 only.
    assert(hash_variant_id == 1);

    let address_hash = crate::hash_keccak::hash_address(account_address);
    crate::mpt_simplified::assert_account_path(address_hash, path_nibbles);

    // Bounded proof shape from current sample data: 3 branch nodes + 1 leaf.
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

    // Bind decoded account fields supplied from baseline-normalized witness.
    let recomputed_leaf_commitment = crate::types::compute_leaf_fields_commitment(
        nonce,
        balance,
        storage_root,
        code_hash,
    );
    assert(recomputed_leaf_commitment == leaf_value_commitment);
}
