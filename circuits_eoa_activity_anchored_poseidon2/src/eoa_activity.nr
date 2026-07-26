pub fn statement_tag() -> Field {
    4
}

fn select_terminal_node(
    node_bytes: [[u8; 1024]; 16],
    node_lengths: [Field; 16],
    active_node_count: Field,
) -> ([u8; 1024], Field) {
    let active_node_count_u32 = active_node_count as u32;
    assert(active_node_count == active_node_count_u32 as Field);
    assert(active_node_count_u32 >= 1);
    assert(active_node_count_u32 <= crate::expanded_mpt_capacity::max_proof_nodes());

    let terminal_index = active_node_count_u32 - 1;
    let mut selected_bytes = [0; 1024];
    let mut selected_len: Field = 0;
    for i in 0..16 {
        if (i as u32) == terminal_index {
            selected_bytes = node_bytes[i];
            selected_len = node_lengths[i];
        }
    }
    (selected_bytes, selected_len)
}

fn prove_one(
    witness_version: Field,
    state_root: [u8; 32],
    state_root_field: Field,
    account_address: [u8; 20],
    private_trie_key: [u8; 32],
    private_address_hash: [u8; 32],
    account_proof_depth: Field,
    node_bytes: [[u8; 1024]; 16],
    node_lengths: [Field; 16],
    node_kinds: [Field; 16],
    node_list_layouts: [[Field; 4]; 16],
    node_item_layouts: [[[Field; 4]; 17]; 16],
    node_compact_layouts: [[Field; 4]; 16],
    selected_ref_layouts: [[Field; 4]; 16],
    selected_ref_bytes: [[u8; 32]; 16],
    selected_ref_lengths: [Field; 16],
    selected_ref_kinds: [Field; 16],
    terminal_value: [u8; 256],
    terminal_value_len: Field,
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
    private_branch_child_hash_fields: [Field; 3],
    private_branch_children_fields: [[Field; 16]; 3],
) {
    let _ = leaf_path_nibbles;
    let _ = leaf_path_len;
    assert(crate::expanded_hash_poseidon2::bytes32_to_field(state_root) == state_root_field);
    assert(
        crate::expanded_hash_poseidon2::bytes32_to_field(private_address_hash)
            == crate::hash_poseidon2::hash_address_field(account_address),
    );
    assert(private_trie_key == private_address_hash);

    let authenticated = crate::expanded_account_verifier::assert_inclusion(
        witness_version,
        state_root,
        state_root_field,
        private_trie_key,
        account_proof_depth,
        node_bytes,
        node_lengths,
        node_kinds,
        node_list_layouts,
        node_item_layouts,
        node_compact_layouts,
        selected_ref_layouts,
        selected_ref_bytes,
        selected_ref_lengths,
        selected_ref_kinds,
        terminal_value,
        terminal_value_len,
    );

    for i in 0..3 {
        assert(
            crate::expanded_hash_poseidon2::bytes32_to_field(selected_ref_bytes[i])
                == private_branch_child_hash_fields[i],
        );
    }

    let (terminal_node_bytes, terminal_node_len) = select_terminal_node(
        node_bytes,
        node_lengths,
        account_proof_depth,
    );

    crate::rlp_balance::assert_eoa_account_layout_expanded(
        terminal_node_bytes,
        terminal_node_len,
        authenticated.value_bytes,
        authenticated.value_len,
        leaf_outer_list_layout,
        leaf_compact_path_layout,
        leaf_account_value_layout,
        account_inner_list_layout,
        account_nonce_layout,
        account_balance_layout,
        account_storage_root_layout,
        account_code_hash_layout,
    );

    let _ = private_branch_children_fields;
}

pub fn prove(
    witness_version: Field,
    public_hash_variant_id: Field,
    public_account_address: [u8; 20],
    public_state_root_1: [u8; 32],
    public_state_root_1_field: Field,
    public_state_root_2: [u8; 32],
    public_state_root_2_field: Field,
    private_trie_key_1: [u8; 32],
    private_active_node_count_1: Field,
    private_node_bytes_1: [[u8; 1024]; 16],
    private_node_lengths_1: [Field; 16],
    private_node_kinds_1: [Field; 16],
    private_node_list_layouts_1: [[Field; 4]; 16],
    private_node_item_layouts_1: [[[Field; 4]; 17]; 16],
    private_node_compact_layouts_1: [[Field; 4]; 16],
    private_selected_ref_layouts_1: [[Field; 4]; 16],
    private_selected_ref_bytes_1: [[u8; 32]; 16],
    private_selected_ref_lengths_1: [Field; 16],
    private_selected_ref_kinds_1: [Field; 16],
    private_terminal_value_1: [u8; 256],
    private_terminal_value_len_1: Field,
    private_leaf_path_nibbles_1: [Field; 64],
    private_leaf_path_len_1: Field,
    private_leaf_outer_list_layout_1: [Field; 4],
    private_leaf_compact_path_layout_1: [Field; 4],
    private_leaf_account_value_layout_1: [Field; 4],
    private_account_inner_list_layout_1: [Field; 4],
    private_account_nonce_layout_1: [Field; 4],
    private_account_balance_layout_1: [Field; 4],
    private_account_storage_root_layout_1: [Field; 4],
    private_account_code_hash_layout_1: [Field; 4],
    private_address_hash_1: [u8; 32],
    private_branch_child_hash_fields_1: [Field; 3],
    private_branch_children_fields_1: [[Field; 16]; 3],
    private_trie_key_2: [u8; 32],
    private_active_node_count_2: Field,
    private_node_bytes_2: [[u8; 1024]; 16],
    private_node_lengths_2: [Field; 16],
    private_node_kinds_2: [Field; 16],
    private_node_list_layouts_2: [[Field; 4]; 16],
    private_node_item_layouts_2: [[[Field; 4]; 17]; 16],
    private_node_compact_layouts_2: [[Field; 4]; 16],
    private_selected_ref_layouts_2: [[Field; 4]; 16],
    private_selected_ref_bytes_2: [[u8; 32]; 16],
    private_selected_ref_lengths_2: [Field; 16],
    private_selected_ref_kinds_2: [Field; 16],
    private_terminal_value_2: [u8; 256],
    private_terminal_value_len_2: Field,
    private_leaf_path_nibbles_2: [Field; 64],
    private_leaf_path_len_2: Field,
    private_leaf_outer_list_layout_2: [Field; 4],
    private_leaf_compact_path_layout_2: [Field; 4],
    private_leaf_account_value_layout_2: [Field; 4],
    private_account_inner_list_layout_2: [Field; 4],
    private_account_nonce_layout_2: [Field; 4],
    private_account_balance_layout_2: [Field; 4],
    private_account_storage_root_layout_2: [Field; 4],
    private_account_code_hash_layout_2: [Field; 4],
    private_address_hash_2: [u8; 32],
    private_branch_child_hash_fields_2: [Field; 3],
    private_branch_children_fields_2: [[Field; 16]; 3],
) {
    assert(public_hash_variant_id == 2);

    prove_one(
        witness_version,
        public_state_root_1,
        public_state_root_1_field,
        public_account_address,
        private_trie_key_1,
        private_address_hash_1,
        private_active_node_count_1,
        private_node_bytes_1,
        private_node_lengths_1,
        private_node_kinds_1,
        private_node_list_layouts_1,
        private_node_item_layouts_1,
        private_node_compact_layouts_1,
        private_selected_ref_layouts_1,
        private_selected_ref_bytes_1,
        private_selected_ref_lengths_1,
        private_selected_ref_kinds_1,
        private_terminal_value_1,
        private_terminal_value_len_1,
        private_leaf_path_nibbles_1,
        private_leaf_path_len_1,
        private_leaf_outer_list_layout_1,
        private_leaf_compact_path_layout_1,
        private_leaf_account_value_layout_1,
        private_account_inner_list_layout_1,
        private_account_nonce_layout_1,
        private_account_balance_layout_1,
        private_account_storage_root_layout_1,
        private_account_code_hash_layout_1,
        private_branch_child_hash_fields_1,
        private_branch_children_fields_1,
    );
    prove_one(
        witness_version,
        public_state_root_2,
        public_state_root_2_field,
        public_account_address,
        private_trie_key_2,
        private_address_hash_2,
        private_active_node_count_2,
        private_node_bytes_2,
        private_node_lengths_2,
        private_node_kinds_2,
        private_node_list_layouts_2,
        private_node_item_layouts_2,
        private_node_compact_layouts_2,
        private_selected_ref_layouts_2,
        private_selected_ref_bytes_2,
        private_selected_ref_lengths_2,
        private_selected_ref_kinds_2,
        private_terminal_value_2,
        private_terminal_value_len_2,
        private_leaf_path_nibbles_2,
        private_leaf_path_len_2,
        private_leaf_outer_list_layout_2,
        private_leaf_compact_path_layout_2,
        private_leaf_account_value_layout_2,
        private_account_inner_list_layout_2,
        private_account_nonce_layout_2,
        private_account_balance_layout_2,
        private_account_storage_root_layout_2,
        private_account_code_hash_layout_2,
        private_branch_child_hash_fields_2,
        private_branch_children_fields_2,
    );

    let (terminal_node_bytes_1, _) = select_terminal_node(
        private_node_bytes_1,
        private_node_lengths_1,
        private_active_node_count_1,
    );
    let (terminal_node_bytes_2, _) = select_terminal_node(
        private_node_bytes_2,
        private_node_lengths_2,
        private_active_node_count_2,
    );

    crate::rlp_balance::assert_nonce_encoding_differs_expanded(
        terminal_node_bytes_1,
        private_account_nonce_layout_1,
        terminal_node_bytes_2,
        private_account_nonce_layout_2,
    );
}
