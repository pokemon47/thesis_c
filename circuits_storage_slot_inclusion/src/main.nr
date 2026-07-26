mod hash_keccak;
mod mpt_simplified;
mod storage_leaf_verifier;
mod types;
mod variable_depth_account_verifier;

fn main(
    public_hash_variant_id: pub Field,
    public_state_root: pub [u8; 32],
    public_contract_address: pub [u8; 20],
    public_storage_slot: pub [u8; 32],
    public_expected_storage_value: pub [u8; 32],
    private_node_rlp_bytes: [[u8; 544]; 4],
    private_node_rlp_lens: [Field; 4],
    private_node_kinds: [Field; 4],
    private_branch_child_indices: [Field; 3],
    private_branch_child_hashes: [[u8; 32]; 3],
    private_branch_children: [[[u8; 32]; 16]; 3],
    private_path_nibbles: [Field; 64],
    private_leaf_path_nibbles: [Field; 64],
    private_leaf_path_len: Field,
    private_account_proof_depth: Field,
    private_leaf_outer_list_layout: [Field; 4],
    private_leaf_compact_path_layout: [Field; 4],
    private_leaf_account_value_layout: [Field; 4],
    private_account_inner_list_layout: [Field; 4],
    private_account_nonce_layout: [Field; 4],
    private_account_balance_layout: [Field; 4],
    private_account_storage_root_layout: [Field; 4],
    private_account_code_hash_layout: [Field; 4],
    private_storage_node_rlp_bytes: [[u8; 544]; 1],
    private_storage_node_rlp_len: Field,
    private_storage_proof_depth: Field,
    private_storage_path_nibbles: [Field; 64],
    private_storage_path_len: Field,
    private_storage_leaf_outer_list_layout: [Field; 4],
    private_storage_leaf_compact_path_layout: [Field; 4],
    private_storage_value_item_layout: [Field; 4],
    private_storage_value_payload_offset: Field,
    private_storage_value_payload_len: Field,
    private_storage_value_active_bytes: [u8; 32],
    private_storage_value_active_len: Field,
    private_storage_value_padded: [u8; 32],
    private_storage_key_hash: [u8; 32],
) {
    assert(public_hash_variant_id == 1);
    assert(private_storage_proof_depth == 1);
    assert(private_storage_value_payload_offset == private_storage_value_item_layout[2]);
    assert(private_storage_value_payload_len == private_storage_value_item_layout[3]);

    crate::variable_depth_account_verifier::assert_variable_depth_keccak(
        public_state_root,
        public_contract_address,
        private_account_proof_depth,
        private_node_rlp_bytes,
        private_node_rlp_lens,
        private_node_kinds,
        private_branch_child_indices,
        private_branch_child_hashes,
        private_branch_children,
        private_path_nibbles,
        private_leaf_path_nibbles,
        private_leaf_path_len,
        private_leaf_outer_list_layout,
        private_leaf_compact_path_layout,
        private_leaf_account_value_layout,
        private_account_inner_list_layout,
        private_account_nonce_layout,
        private_account_balance_layout,
        private_account_storage_root_layout,
        private_account_code_hash_layout,
    );

    let authenticated = crate::variable_depth_account_verifier::authenticated_terminal(
        private_account_proof_depth,
        private_node_rlp_bytes,
        private_node_rlp_lens,
        private_node_kinds,
        private_branch_child_indices,
        private_branch_child_hashes,
        private_branch_children,
        private_path_nibbles,
        private_leaf_path_nibbles,
        private_leaf_path_len,
        private_leaf_account_value_layout,
    );
    let authenticated_storage_root = crate::storage_leaf_verifier::extract_storage_root(
        authenticated.terminal_node_bytes,
        private_account_storage_root_layout,
    );

    crate::storage_leaf_verifier::assert_one_node_storage_leaf(
        private_storage_node_rlp_bytes[0],
        private_storage_node_rlp_len,
        authenticated_storage_root,
        public_storage_slot,
        private_storage_key_hash,
        private_storage_path_nibbles,
        private_storage_path_len,
        private_storage_leaf_outer_list_layout,
        private_storage_leaf_compact_path_layout,
        private_storage_value_item_layout,
        private_storage_value_active_bytes,
        private_storage_value_active_len,
        private_storage_value_padded,
        public_expected_storage_value,
    );
}
