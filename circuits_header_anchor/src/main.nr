mod expanded_header_capacity;
mod header_anchor;
mod header_fixtures;
mod rlp;

fn main(
    public_block_hash: pub [u8; 32],
    public_expected_state_root: pub [u8; 32],
    witness_version: Field,
    private_header_bytes: [u8; 640],
    private_header_len: Field,
) {
    header_anchor::assert_header_anchor(
        public_block_hash,
        public_expected_state_root,
        witness_version,
        private_header_bytes,
        private_header_len,
    );
}
