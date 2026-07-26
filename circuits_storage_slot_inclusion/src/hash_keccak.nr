use dep::keccak256::keccak256;

pub fn hash_tag() -> Field {
    11
}

pub fn hash_node(input: [u8; 544], input_len: Field) -> [u8; 32] {
    let len_u32 = input_len as u32;
    keccak256(input, len_u32)
}

pub fn hash_address(input: [u8; 20]) -> [u8; 32] {
    keccak256(input, 20)
}

pub fn hash_storage_slot(input: [u8; 32]) -> [u8; 32] {
    keccak256(input, 32)
}
