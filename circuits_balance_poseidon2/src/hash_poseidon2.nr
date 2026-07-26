use poseidon::poseidon2::Poseidon2;

global PACKED_NODE_FIELDS: u32 = 18;

pub fn hash_tag() -> Field {
    12
}

fn pack_31_bytes_little_endian(bytes: [u8; 31]) -> Field {
    let mut field = 0;
    let mut offset = 1;
    for i in 0..31 {
        field += (bytes[i] as Field) * offset;
        offset *= 256;
    }
    field
}

fn pack_20_bytes_little_endian(bytes: [u8; 20]) -> Field {
    let mut field = 0;
    let mut offset = 1;
    for i in 0..20 {
        field += (bytes[i] as Field) * offset;
        offset *= 256;
    }
    field
}

pub fn hash_address_field(input: [u8; 20]) -> Field {
    Poseidon2::hash([pack_20_bytes_little_endian(input)], 1)
}

pub fn hash_bytes_544(input: [u8; 544], input_len: Field) -> Field {
    let len_u32 = input_len as u32;
    assert(input_len == len_u32 as Field);
    assert(len_u32 <= 544);

    let mut packed_fields: [Field; PACKED_NODE_FIELDS] = [0; PACKED_NODE_FIELDS];
    let mut current_field = [0; 31];
    let mut packed_field_count = 0;

    for i in 0..544 {
        if i < len_u32 {
            let index = i % 31;
            current_field[index] = input[i];

            if index == 30 {
                packed_fields[packed_field_count] = pack_31_bytes_little_endian(current_field);
                current_field = [0; 31];
                packed_field_count += 1;
            }
        }
    }

    if len_u32 % 31 != 0 {
        packed_fields[packed_field_count] = pack_31_bytes_little_endian(current_field);
        packed_field_count += 1;
    }

    Poseidon2::hash(packed_fields, packed_field_count)
}

pub fn hash_node_field(input: [u8; 544], input_len: Field) -> Field {
    hash_bytes_544(input, input_len)
}

fn test_buffer_with_suffix(suffix: u8) -> [u8; 544] {
    let mut input = [0; 544];
    input[0] = 0x01;
    input[1] = 0x02;
    input[2] = suffix;
    input
}

#[test]
fn test_poseidon2_byte_vectors() {
    let mut empty_input = [0; 544];
    assert_eq(
        hash_bytes_544(empty_input, 0),
        0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e,
    );

    empty_input[0] = 0x00;
    assert_eq(
        hash_bytes_544(empty_input, 1),
        0x2710144414c3a5f2354f4c08d52ed655b9fe253b4bf12cb9ad3de693d9b1db11,
    );

    let mut one_input = [0; 544];
    one_input[0] = 0x01;
    assert_eq(
        hash_bytes_544(one_input, 1),
        0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
    );

    let mut ff_input = [0; 544];
    ff_input[0] = 0xff;
    assert_eq(
        hash_bytes_544(ff_input, 1),
        0x238f5dc3e88d1e959c7185cea4df0e3ea293e80c305545e83270e937b98f0811,
    );

    let mut two_input = [0; 544];
    two_input[0] = 0x01;
    two_input[1] = 0x02;
    assert_eq(
        hash_bytes_544(two_input, 2),
        0x0656a3182cf754756fb139bd783186c12077b3677af55c1876e25ff8da2387e0,
    );
}

#[test]
fn test_poseidon2_chunk_boundaries() {
    let mut input = [0; 544];
    for i in 0..64 {
        input[i] = i as u8;
    }

    assert_eq(
        hash_bytes_544(input, 31),
        0x1da6c60e1ec461d10e97b80e95ff204b7991e72fbe1cd28bc5c9f784f4bfe366,
    );
    assert_eq(
        hash_bytes_544(input, 32),
        0x19cc7a6bc7dbaac9036934fa1b9efd6e966ba1184eba754409cf993ffacaada8,
    );
    assert_eq(
        hash_bytes_544(input, 33),
        0x1f3f3008d5073024f3c98e107bf479fd460d546677e427df578afd01c6d19766,
    );
    assert_eq(
        hash_bytes_544(input, 62),
        0x2d8af91d372c0aaf31b467c7fe935486a93c57bbdddbd6684ef5b7448192454e,
    );
    assert_eq(
        hash_bytes_544(input, 63),
        0x0c22a723098a4b56a107640c4e75288d4d20c86598f7f00b45e68df6ac774967,
    );
    assert_eq(
        hash_bytes_544(input, 64),
        0x0ad31f49bcfa6f65c7d9cd0b0b59847f9835180bfaf34961ad2fe829f0868785,
    );
}

#[test]
fn test_poseidon2_declared_length_and_trailing_zero_equivalence() {
    let mut one = [0; 544];
    let mut one_zero = [0; 544];
    let mut one_zero_zero = [0; 544];
    one[0] = 0x01;
    one_zero[0] = 0x01;
    one_zero[1] = 0x00;
    one_zero_zero[0] = 0x01;
    one_zero_zero[1] = 0x00;
    one_zero_zero[2] = 0x00;

    let one_hash = hash_bytes_544(one, 1);
    assert_eq(one_hash, hash_bytes_544(one_zero, 2));
    assert_eq(one_hash, hash_bytes_544(one_zero_zero, 3));

    let suffix_a = test_buffer_with_suffix(99);
    let suffix_b = test_buffer_with_suffix(11);
    assert_eq(hash_bytes_544(suffix_a, 2), hash_bytes_544(suffix_b, 2));
}
