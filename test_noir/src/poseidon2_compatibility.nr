use poseidon::{poseidon2_permutation, poseidon2::Poseidon2};

pub fn raw_permutation_compatibility() -> [Field; 4] {
    poseidon2_permutation([0, 1, 2, 3])
}

pub fn fixed_len_hash_empty() -> Field {
    Poseidon2::hash([0, 0, 0, 0, 0], 0)
}

pub fn fixed_len_hash_0(input: [Field; 1]) -> Field {
    Poseidon2::hash(input, input.len())
}

pub fn fixed_len_hash_1(input: [Field; 1]) -> Field {
    Poseidon2::hash(input, input.len())
}

pub fn fixed_len_hash_2(input: [Field; 2]) -> Field {
    Poseidon2::hash(input, input.len())
}

pub fn fixed_len_hash_3(input: [Field; 3]) -> Field {
    Poseidon2::hash(input, input.len())
}

pub fn fixed_len_hash_4(input: [Field; 4]) -> Field {
    Poseidon2::hash(input, input.len())
}

pub fn fixed_len_hash_5(input: [Field; 5]) -> Field {
    Poseidon2::hash(input, input.len())
}

pub fn fixed_len_hash_8(input: [Field; 8]) -> Field {
    Poseidon2::hash(input, input.len())
}

pub fn fixed_len_hash_p_minus_one() -> Field {
    Poseidon2::hash([0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000], 1)
}

pub fn variable_len_hash_5(input: [Field; 5], message_size: u32) -> Field {
    Poseidon2::hash(input, message_size)
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

pub fn poseidon2_hash_bytes_like<let N: u32>(bytes: [u8; N]) -> ([Field; 3], u32, Field) {
    let mut packed_fields = [0; 3];
    let mut current_field = [0; 31];
    let mut packed_field_count = 0;

    for i in 0..bytes.len() {
        let index = i % 31;
        current_field[index] = bytes[i];

        if index == 30 {
            packed_fields[packed_field_count] = pack_31_bytes_little_endian(current_field);
            current_field = [0; 31];
            packed_field_count += 1;
        }
    }

    if bytes.len() % 31 != 0 {
        packed_fields[packed_field_count] = pack_31_bytes_little_endian(current_field);
        packed_field_count += 1;
    }

    let hash = Poseidon2::hash(packed_fields, packed_field_count);
    (packed_fields, packed_field_count, hash)
}

pub fn empty_message_hash() -> Field {
    Poseidon2::hash([0, 0, 0, 0, 0], 0)
}

#[test]
fn test_raw_permutation() {
    let out = raw_permutation_compatibility();
    assert_eq(
        out,
        [
            0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737,
            0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662,
            0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb,
            0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a,
        ],
    );
}

#[test]
fn test_fixed_len_hash_vectors() {
    assert_eq(
        fixed_len_hash_empty(),
        0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e,
    );
    assert_eq(fixed_len_hash_0([0]), 0x2710144414c3a5f2354f4c08d52ed655b9fe253b4bf12cb9ad3de693d9b1db11);
    assert_eq(fixed_len_hash_1([1]), 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373);
    assert_eq(
        fixed_len_hash_2([0, 1]),
        0x0dd6d785caa3fe1ad139a40b6bd26fccbd6c8697573b0e34489c740533db5cc8,
    );
    assert_eq(
        fixed_len_hash_3([0, 1, 2]),
        0x099f9ef8a2ccf575306ef6b7996be65db5e47d860bfab6592e52c89764b4b9cc,
    );
    assert_eq(
        fixed_len_hash_4([0, 1, 2, 3]),
        0x109dc2e0b6bad6e1f2954e9ea0b58462c30257ad3876eae682ed33a22992f427,
    );
    assert_eq(
        fixed_len_hash_5([0, 1, 2, 3, 4]),
        0x1b94975e2fed61b208fdf956b8f35d1e893edd2dd445a70dd46c881d57a5900d,
    );
    assert_eq(
        fixed_len_hash_8([0, 1, 2, 3, 4, 5, 6, 7]),
        0x18361958a14c826b2a18aa1b2b8dc8daeba0da8ae2a1823c46a7dd57a6c76161,
    );
    assert_eq(
        fixed_len_hash_p_minus_one(),
        0x2a83b51f6c23d49f641e585d127b2367c05060f5da58c3bb891818ca5f725eec,
    );
}

#[test]
fn test_variable_len_padding_and_prefix() {
    let a = [1, 2, 99, 98, 97];
    let b = [1, 2, 11, 12, 13];
    let c = [3, 2, 99, 98, 97];

    assert(variable_len_hash_5([0, 0, 0, 0, 0], 0) == fixed_len_hash_empty());
    assert(variable_len_hash_5([1, 0, 0, 0, 0], 1) == fixed_len_hash_1([1]));
    assert(variable_len_hash_5([1, 2, 0, 0, 0], 2) == fixed_len_hash_2([1, 2]));
    assert(variable_len_hash_5([1, 2, 3, 0, 0], 3) == fixed_len_hash_3([1, 2, 3]));
    assert(variable_len_hash_5([1, 2, 3, 4, 0], 4) == fixed_len_hash_4([1, 2, 3, 4]));

    assert_eq(
        variable_len_hash_5([0, 0, 0, 0, 0], 0),
        0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e,
    );
    assert_eq(
        variable_len_hash_5([1, 0, 0, 0, 0], 1),
        0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
    );
    assert_eq(
        variable_len_hash_5([1, 2, 0, 0, 0], 2),
        0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
    );
    assert_eq(
        variable_len_hash_5([1, 2, 3, 0, 0], 3),
        0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
    );
    assert_eq(
        variable_len_hash_5([1, 2, 3, 4, 0], 4),
        0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9,
    );

    let a_hash = variable_len_hash_5(a, 2);
    let b_hash = variable_len_hash_5(b, 2);
    let c_hash = variable_len_hash_5(c, 2);

    assert_eq(a_hash, b_hash);
    assert(a_hash != c_hash);
}

#[test]
fn test_poseidon2_byte_packing_and_hashing() {
    let (empty_fields, empty_count, empty_hash) = poseidon2_hash_bytes_like([]);
    let (zero_fields, zero_count, zero_hash) = poseidon2_hash_bytes_like([0x00]);
    let (one_fields, one_count, one_hash) = poseidon2_hash_bytes_like([0x01]);
    let (one_zero_fields, one_zero_count, one_zero_hash) = poseidon2_hash_bytes_like([0x01, 0x00]);
    let (one_zero_zero_fields, one_zero_zero_count, one_zero_zero_hash) =
        poseidon2_hash_bytes_like([0x01, 0x00, 0x00]);
    let (two_fields, two_count, two_hash) = poseidon2_hash_bytes_like([0x01, 0x02]);
    let (thirty_one_fields, thirty_one_count, thirty_one_hash) =
        poseidon2_hash_bytes_like([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e,
        ]);
    let (thirty_two_fields, thirty_two_count, thirty_two_hash) =
        poseidon2_hash_bytes_like([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
    let (thirty_three_fields, thirty_three_count, thirty_three_hash) =
        poseidon2_hash_bytes_like([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ]);
    let (sixty_two_fields, sixty_two_count, sixty_two_hash) = poseidon2_hash_bytes_like([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d,
    ]);
    let (sixty_three_fields, sixty_three_count, sixty_three_hash) = poseidon2_hash_bytes_like([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e,
    ]);
    let (sixty_four_fields, sixty_four_count, sixty_four_hash) = poseidon2_hash_bytes_like([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ]);

    assert_eq(empty_count, 0);
    assert_eq(zero_count, 1);
    assert_eq(one_count, 1);
    assert_eq(one_zero_count, 1);
    assert_eq(one_zero_zero_count, 1);
    assert_eq(two_count, 1);
    assert_eq(thirty_one_count, 1);
    assert_eq(thirty_two_count, 2);
    assert_eq(thirty_three_count, 2);
    assert_eq(sixty_two_count, 2);
    assert_eq(sixty_three_count, 3);
    assert_eq(sixty_four_count, 3);

    assert_eq(one_fields[0], 0x01);
    assert_eq(one_zero_fields[0], 0x01);
    assert_eq(one_zero_zero_fields[0], 0x01);
    assert_eq(two_fields[0], 0x0201);
    assert_eq(thirty_one_fields[0], 0x1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100);
    assert_eq(thirty_two_fields[0], 0x1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100);
    assert_eq(thirty_two_fields[1], 0x1f);
    assert_eq(thirty_three_fields[0], 0x1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100);
    assert_eq(thirty_three_fields[1], 0x201f);
    assert_eq(sixty_two_fields[0], 0x1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100);
    assert_eq(
        sixty_two_fields[1],
        0x3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f,
    );
    assert_eq(sixty_three_fields[2], 0x3e);
    assert_eq(sixty_four_fields[2], 0x3f3e);

    assert_eq(empty_hash, Poseidon2::hash(empty_fields, empty_count));
    assert_eq(zero_hash, Poseidon2::hash(zero_fields, zero_count));
    assert_eq(one_hash, Poseidon2::hash(one_fields, one_count));
    assert_eq(one_zero_hash, Poseidon2::hash(one_zero_fields, one_zero_count));
    assert_eq(one_zero_zero_hash, Poseidon2::hash(one_zero_zero_fields, one_zero_zero_count));
    assert_eq(two_hash, Poseidon2::hash(two_fields, two_count));
    assert_eq(thirty_one_hash, Poseidon2::hash(thirty_one_fields, thirty_one_count));
    assert_eq(thirty_two_hash, Poseidon2::hash(thirty_two_fields, thirty_two_count));
    assert_eq(thirty_three_hash, Poseidon2::hash(thirty_three_fields, thirty_three_count));
    assert_eq(sixty_two_hash, Poseidon2::hash(sixty_two_fields, sixty_two_count));
    assert_eq(sixty_three_hash, Poseidon2::hash(sixty_three_fields, sixty_three_count));
    assert_eq(sixty_four_hash, Poseidon2::hash(sixty_four_fields, sixty_four_count));

    assert_eq(one_hash, one_zero_hash);
    assert_eq(one_hash, one_zero_zero_hash);
    assert(empty_hash != zero_hash);
}
