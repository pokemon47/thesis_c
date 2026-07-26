pub fn statement_tag() -> Field {
    1
}

pub fn prove(
    witness_version: Field,
    state_root: [u8; 32],
    account_address: [u8; 20],
    hash_variant_id: Field,
    leaf_value_commitment: Field,
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
    private_terminal_value: [u8; 256],
    private_terminal_value_len: Field,
    leaf_outer_list_layout: [Field; 4],
    leaf_compact_path_layout: [Field; 4],
    leaf_account_value_layout: [Field; 4],
    account_inner_list_layout: [Field; 4],
    account_nonce_layout: [Field; 4],
    account_balance_layout: [Field; 4],
    account_storage_root_layout: [Field; 4],
    account_code_hash_layout: [Field; 4],
) {
    assert(hash_variant_id == 1);
    assert(crate::hash_keccak::hash_address(account_address) == private_trie_key);

    let authenticated_terminal = crate::expanded_account_verifier::assert_inclusion(
        witness_version,
        state_root,
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

    crate::account_commitment::assert_authenticated_leaf_value_commitment(
        authenticated_terminal.value_bytes,
        authenticated_terminal.value_len,
        leaf_value_commitment,
    );
}
