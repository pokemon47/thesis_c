mod account_inclusion;
mod balance_verification;
mod codehash_verification;
mod eoa_activity;
mod hash_keccak;
mod hash_poseidon2;
mod mpt_simplified;
mod storage_slot_membership;
mod types;

fn main(
    public_state_root: pub [u8; 32],
    public_account_address: pub [u8; 20],
    public_hash_variant_id: pub Field,
    public_leaf_value_commitment: pub Field,
    private_node_rlp_bytes: [[u8; 544]; 4],
    private_node_rlp_lens: [Field; 4],
    private_node_kinds: [Field; 4],
    private_branch_child_indices: [Field; 3],
    private_branch_child_hashes: [[u8; 32]; 3],
    private_branch_children: [[[u8; 32]; 16]; 3],
    private_path_nibbles: [Field; 64],
    private_leaf_path_nibbles: [Field; 64],
    private_leaf_path_len: Field,
    private_nonce: Field,
    private_balance: Field,
    private_storage_root: [u8; 32],
    private_code_hash: [u8; 32],
) {
    account_inclusion::prove(
        public_state_root,
        public_account_address,
        public_hash_variant_id,
        private_node_rlp_bytes,
        private_node_rlp_lens,
        private_node_kinds,
        private_branch_child_indices,
        private_branch_child_hashes,
        private_branch_children,
        private_path_nibbles,
        private_leaf_path_nibbles,
        private_leaf_path_len,
        private_nonce,
        private_balance,
        private_storage_root,
        private_code_hash,
        public_leaf_value_commitment,
    );
}
