mod poseidon2_compatibility;

use poseidon2_compatibility::{
    fixed_len_hash_0, fixed_len_hash_1, fixed_len_hash_2, fixed_len_hash_3, fixed_len_hash_4,
    fixed_len_hash_5, fixed_len_hash_8, fixed_len_hash_empty, fixed_len_hash_p_minus_one,
    poseidon2_hash_bytes_like, raw_permutation_compatibility, variable_len_hash_5,
};

fn main() -> pub (
    [Field; 4],
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    (
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
        ([Field; 3], u32, Field),
    ),
) {
    let raw_permutation = raw_permutation_compatibility();
    let fixed_empty = fixed_len_hash_empty();
    let fixed_0 = fixed_len_hash_0([0]);
    let fixed_1 = fixed_len_hash_1([1]);
    let fixed_2 = fixed_len_hash_2([0, 1]);
    let fixed_3 = fixed_len_hash_3([0, 1, 2]);
    let fixed_4 = fixed_len_hash_4([0, 1, 2, 3]);
    let fixed_5 = fixed_len_hash_5([0, 1, 2, 3, 4]);
    let fixed_8 = fixed_len_hash_8([0, 1, 2, 3, 4, 5, 6, 7]);
    let fixed_p_minus_one = fixed_len_hash_p_minus_one();
    let variable_size_0 = variable_len_hash_5([0, 0, 0, 0, 0], 0);
    let variable_size_1 = variable_len_hash_5([1, 0, 0, 0, 0], 1);
    let variable_size_2 = variable_len_hash_5([1, 2, 0, 0, 0], 2);
    let variable_size_3 = variable_len_hash_5([1, 2, 3, 0, 0], 3);
    let variable_size_4 = variable_len_hash_5([1, 2, 3, 4, 0], 4);
    let padding_a = variable_len_hash_5([1, 2, 99, 98, 97], 2);
    let padding_b = variable_len_hash_5([1, 2, 11, 12, 13], 2);
    let padding_control = variable_len_hash_5([3, 2, 99, 98, 97], 2);
    let empty_bytes: [u8; 0] = [];
    let byte_empty = poseidon2_hash_bytes_like(empty_bytes);
    let byte_one_zero = poseidon2_hash_bytes_like([0x00]);
    let byte_one_one = poseidon2_hash_bytes_like([0x01]);
    let byte_one_ff = poseidon2_hash_bytes_like([0xff]);
    let byte_two_bytes = poseidon2_hash_bytes_like([0x01, 0x02]);
    let byte_trailing_zero_ambiguity_a = poseidon2_hash_bytes_like([0x01]);
    let byte_trailing_zero_ambiguity_b = poseidon2_hash_bytes_like([0x01, 0x00]);
    let byte_trailing_zero_ambiguity_c = poseidon2_hash_bytes_like([0x01, 0x00, 0x00]);
    let byte_thirty_one_bytes = poseidon2_hash_bytes_like([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e,
    ]);
    let byte_thirty_two_bytes = poseidon2_hash_bytes_like([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ]);
    let byte_thirty_three_bytes = poseidon2_hash_bytes_like([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ]);
    let byte_sixty_two_bytes = poseidon2_hash_bytes_like([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
    ]);
    let byte_sixty_three_bytes = poseidon2_hash_bytes_like([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
    ]);
    let byte_sixty_four_bytes = poseidon2_hash_bytes_like([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ]);
    let byte_twenty_byte_address_like = poseidon2_hash_bytes_like([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x10, 0x20, 0x30, 0x40,
    ]);
    let byte_thirty_two_byte_storage_key_like = poseidon2_hash_bytes_like([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
        0xd0, 0xe0, 0xf0, 0x01,
    ]);
    let byte_rlp_like_short_sequence = poseidon2_hash_bytes_like([
        0xc8, 0x01, 0x02, 0x83, 0x61, 0x62, 0x63,
    ]);

    (
        raw_permutation,
        fixed_empty,
        fixed_0,
        fixed_1,
        fixed_2,
        fixed_3,
        fixed_4,
        fixed_5,
        fixed_8,
        fixed_p_minus_one,
        variable_size_0,
        variable_size_1,
        variable_size_2,
        variable_size_3,
        variable_size_4,
        padding_a,
        padding_b,
        padding_control,
        (
            byte_empty,
            byte_one_zero,
            byte_one_one,
            byte_one_ff,
            byte_two_bytes,
            byte_trailing_zero_ambiguity_a,
            byte_trailing_zero_ambiguity_b,
            byte_trailing_zero_ambiguity_c,
            byte_thirty_one_bytes,
            byte_thirty_two_bytes,
            byte_thirty_three_bytes,
            byte_sixty_two_bytes,
            byte_sixty_three_bytes,
            byte_sixty_four_bytes,
            byte_twenty_byte_address_like,
            byte_thirty_two_byte_storage_key_like,
            byte_rlp_like_short_sequence,
        ),
    )
}

#[export]
fn raw_permutation() -> [Field; 4] {
    raw_permutation_compatibility()
}

#[export]
fn fixed_len_hash_empty_export() -> Field {
    fixed_len_hash_empty()
}

#[export]
fn fixed_len_hash_0_export(input: [Field; 1]) -> Field {
    fixed_len_hash_0(input)
}

#[export]
fn fixed_len_hash_1_export(input: [Field; 1]) -> Field {
    fixed_len_hash_1(input)
}

#[export]
fn fixed_len_hash_2_export(input: [Field; 2]) -> Field {
    fixed_len_hash_2(input)
}

#[export]
fn fixed_len_hash_3_export(input: [Field; 3]) -> Field {
    fixed_len_hash_3(input)
}

#[export]
fn fixed_len_hash_4_export(input: [Field; 4]) -> Field {
    fixed_len_hash_4(input)
}

#[export]
fn fixed_len_hash_5_export(input: [Field; 5]) -> Field {
    fixed_len_hash_5(input)
}

#[export]
fn fixed_len_hash_8_export(input: [Field; 8]) -> Field {
    fixed_len_hash_8(input)
}

#[export]
fn variable_len_hash_5_export(input: [Field; 5], message_size: u32) -> Field {
    variable_len_hash_5(input, message_size)
}
