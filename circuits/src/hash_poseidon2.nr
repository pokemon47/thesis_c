pub fn hash_tag() -> Field {
    12
}

pub fn hash_node(_input: [u8; 544], _input_len: Field) -> [u8; 32] {
    // Poseidon2 hash circuit is intentionally not implemented in this first pass.
    // Runner marks Poseidon2 rows as `proxy` or `missing_dataset`.
    assert(false);
    [0; 32]
}

pub fn hash_address(_input: [u8; 20]) -> [u8; 32] {
    assert(false);
    [0; 32]
}
