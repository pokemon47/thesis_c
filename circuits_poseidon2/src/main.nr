mod account_inclusion;
mod account_terminal;
mod expanded_hash_poseidon2;
mod expanded_mpt_capacity;
mod hash_poseidon2;
mod mpt_inclusion;
mod mpt_simplified;
mod types;
mod variable_depth_account_verifier;

fn main(
    public_state_root: pub [u8; 32],
    public_state_root_field: pub Field,
    public_account_address: pub [u8; 20],
    public_hash_variant_id: pub Field,
    witness_version: Field,
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
) {
    account_inclusion::prove(
        public_state_root,
        public_state_root_field,
        public_account_address,
        public_hash_variant_id,
        witness_version,
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
}
