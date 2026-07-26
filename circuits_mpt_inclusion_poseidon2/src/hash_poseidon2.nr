use poseidon::poseidon2::Poseidon2;

global PACKED_NODE_FIELDS: u32 = 34;

fn pack_31(bytes: [u8; 31]) -> Field {
    let mut out = 0;
    let mut scale = 1;
    for i in 0..31 {
        out += (bytes[i] as Field) * scale;
        scale *= 256;
    }
    out
}

pub fn bytes32_to_field(input: [u8; 32]) -> Field {
    let mut out = 0;
    for i in 0..32 {
        out = out * 256 + input[i] as Field;
    }
    out
}

pub fn hash_node(input: [u8; 1024], input_len: Field) -> Field {
    let len = input_len as u32;
    assert(input_len == len as Field);
    assert(len <= 1024);
    let mut packed: [Field; PACKED_NODE_FIELDS] = [0; PACKED_NODE_FIELDS];
    let mut chunk = [0; 31];
    let mut count = 0;
    for i in 0..1024 {
        if i < len {
            let j = i % 31;
            chunk[j] = input[i];
            if j == 30 {
                packed[count] = pack_31(chunk);
                chunk = [0; 31];
                count += 1;
            }
        }
    }
    if len % 31 != 0 {
        packed[count] = pack_31(chunk);
        count += 1;
    }
    Poseidon2::hash(packed, count)
}
