use ::keccak256::keccak256;

pub fn hash_node(input: [u8; 1024], input_len: Field) -> [u8; 32] {
    let len = input_len as u32;
    assert(input_len == len as Field);
    assert(len <= 1024);
    keccak256(input, len)
}
