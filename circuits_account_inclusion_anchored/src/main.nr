mod account_commitment;
mod account_inclusion;
mod expanded_account_verifier;
mod expanded_header_capacity;
mod expanded_hash_keccak;
mod expanded_mpt_capacity;
mod hash_keccak;
mod header_anchor;
mod header_fixtures;
mod mpt_simplified;
mod rlp;
mod types;

fn main(
    public_block_hash: pub [u8; 32],
    public_state_root: pub [u8; 32],
    public_account_address: pub [u8; 20],
    public_hash_variant_id: pub Field,
    public_leaf_value_commitment: pub Field,
    header_witness_version: Field,
    private_header_bytes: [u8; 640],
    private_header_len: Field,
    account_witness_version: Field,
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
    private_leaf_outer_list_layout: [Field; 4],
    private_leaf_compact_path_layout: [Field; 4],
    private_leaf_account_value_layout: [Field; 4],
    private_account_inner_list_layout: [Field; 4],
    private_account_nonce_layout: [Field; 4],
    private_account_balance_layout: [Field; 4],
    private_account_storage_root_layout: [Field; 4],
    private_account_code_hash_layout: [Field; 4],
) {
    header_anchor::assert_header_anchor(
        public_block_hash,
        public_state_root,
        header_witness_version,
        private_header_bytes,
        private_header_len,
    );

    account_inclusion::prove(
        account_witness_version,
        public_state_root,
        public_account_address,
        public_hash_variant_id,
        public_leaf_value_commitment,
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
        private_leaf_outer_list_layout,
        private_leaf_compact_path_layout,
        private_leaf_account_value_layout,
        private_account_inner_list_layout,
        private_account_nonce_layout,
        private_account_balance_layout,
        private_account_storage_root_layout,
        private_account_code_hash_layout,
    );
}
