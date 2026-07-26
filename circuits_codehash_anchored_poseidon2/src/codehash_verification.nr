pub fn statement_tag() -> Field {
    3
}

fn assert_expected_code_hash(
    leaf_node: [u8; 1024],
    leaf_node_len: Field,
    expected_code_hash: [u8; 32],
    code_hash_layout: [Field; 4],
) {
    crate::types::rlp_account::assert_canonical_bytes32_item(
        leaf_node,
        code_hash_layout,
        leaf_node_len,
    );
    let code_hash_offset = code_hash_layout[2] as u32;
    for i in 0..32 {
        assert(leaf_node[code_hash_offset + i] == expected_code_hash[i]);
    }
}

pub fn prove(
    witness_version: Field,
    state_root: [u8; 32],
    state_root_field: Field,
    account_address: [u8; 20],
    expected_code_hash: [u8; 32],
    hash_variant_id: Field,
    private_state_root_field: Field,
    private_trie_key: [u8; 32],
    private_active_node_count: Field,
    private_node_bytes: [[u8; 1024]; 16],
    private_node_lengths: [Field; 16],
    private_node_kinds: [Field; 16],
    private_node_list_layouts: [[Field; 4]; 16],
    private_node_item_layouts: [[[Field; 4]; 17]; 16],
    private_node_compact_layouts: [[Field; 4]; 16],
    private_selected_ref_layouts: [[Field; 4]; 16],
    private_selected_ref_bytes: [[u8; 32]; 16],
    private_selected_ref_lengths: [Field; 16],
    private_selected_ref_kinds: [Field; 16],
    private_leaf_path_nibbles: [Field; 64],
    private_leaf_path_len: Field,
    private_address_hash: [u8; 32],
    private_terminal_value: [u8; 256],
    private_terminal_value_len: Field,
    private_leaf_outer_list_layout: [Field; 4],
    private_leaf_compact_path_layout: [Field; 4],
    private_leaf_account_value_layout: [Field; 4],
    private_account_inner_list_layout: [Field; 4],
    private_account_nonce_layout: [Field; 4],
    private_account_balance_layout: [Field; 4],
    private_account_storage_root_layout: [Field; 4],
    private_account_code_hash_layout: [Field; 4],
) {
    assert(hash_variant_id == 2);
    assert(crate::types::canonical_bytes32_to_field(state_root) == state_root_field);
    assert(state_root_field == private_state_root_field);
    assert(crate::types::canonical_bytes32_to_field(private_address_hash) == crate::hash_poseidon2::hash_address_field(account_address));
    assert(private_trie_key == private_address_hash);

    crate::variable_depth_account_verifier::assert_inclusion(
        witness_version,
        state_root,
        private_state_root_field,
        private_trie_key,
        private_active_node_count,
        private_node_bytes,
        private_node_lengths,
        private_node_kinds,
        private_node_list_layouts,
        private_node_item_layouts,
        private_node_compact_layouts,
        private_selected_ref_layouts,
        private_selected_ref_bytes,
        private_selected_ref_lengths,
        private_selected_ref_kinds,
        private_terminal_value,
        private_terminal_value_len,
    );

    let active_count = private_active_node_count as u32;
    let terminal_index = active_count - 1;
    let terminal_leaf = private_node_bytes[terminal_index];
    let terminal_leaf_len = private_node_lengths[terminal_index];

    crate::types::rlp_account::assert_canonical_terminal_leaf_and_account_rlp(
        terminal_leaf,
        terminal_leaf_len,
        private_leaf_outer_list_layout,
        private_leaf_compact_path_layout,
        private_leaf_account_value_layout,
        private_account_inner_list_layout,
        private_account_nonce_layout,
        private_account_balance_layout,
        private_account_storage_root_layout,
        private_account_code_hash_layout,
        private_leaf_path_nibbles,
        private_leaf_path_len,
    );
    assert_expected_code_hash(
        terminal_leaf,
        terminal_leaf_len,
        expected_code_hash,
        private_account_code_hash_layout,
    );
}
