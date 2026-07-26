global MAX_ACCOUNT_PROOF_NODES: u32 = 4;
global MAX_ACCOUNT_NODE_BYTES: u32 = 544;
global ACCOUNT_PATH_NIBBLES: u32 = 64;
global MAX_LEAF_PATH_NIBBLES: u32 = 64;
global MAX_BRANCH_NODES: u32 = 3;
global BRANCH_CHILD_SLOTS: u32 = 16;

pub fn assert_nibble(value: Field) {
    assert((value as u32) < BRANCH_CHILD_SLOTS);
}

pub fn bytes32_to_field(input: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 256 + input[i] as Field;
    }
    acc
}

pub fn assert_canonical_field_bytes32(input: [u8; 32]) {
    let modulus: [u8; 32] = [
        48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93,
        40, 51, 232, 72, 121, 185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1,
    ];
    let mut equal_prefix = true;
    let mut less_than_modulus = false;

    for i in 0..32 {
        if equal_prefix {
            if input[i] < modulus[i] {
                less_than_modulus = true;
                equal_prefix = false;
            } else if input[i] > modulus[i] {
                equal_prefix = false;
            }
        }
    }

    assert(less_than_modulus);
}

pub fn canonical_bytes32_to_field(input: [u8; 32]) -> Field {
    assert_canonical_field_bytes32(input);
    bytes32_to_field(input)
}

pub fn bytes20_to_field(input: [u8; 20]) -> Field {
    let mut acc: Field = 0;
    for i in 0..20 {
        acc = acc * 256 + input[i] as Field;
    }
    acc
}

pub fn compute_leaf_fields_commitment(
    nonce: Field,
    balance: Field,
    storage_root: [u8; 32],
    code_hash: [u8; 32],
) -> Field {
    let mut acc = nonce + balance * 17;
    for i in 0..32 {
        acc = acc * 257 + storage_root[i] as Field;
    }
    for i in 0..32 {
        acc = acc * 263 + code_hash[i] as Field;
    }
    acc
}

pub mod rlp_account;

#[test]
fn test_canonical_bytes32_to_field_poseidon2_vectors() {
    assert_eq(
        canonical_bytes32_to_field([
            24, 223, 184, 220, 155, 130, 34, 156, 255, 151, 78, 254, 252, 141, 247, 139,
            28, 233, 109, 157, 132, 66, 54, 180, 150, 120, 92, 105, 139, 198, 115, 46,
        ]),
        0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e,
    );
    assert_eq(
        canonical_bytes32_to_field([
            22, 135, 88, 51, 45, 91, 62, 45, 19, 190, 128, 72, 200, 1, 27, 69,
            69, 144, 224, 108, 68, 188, 231, 247, 2, 240, 145, 3, 238, 245, 163, 115,
        ]),
        0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
    );
    assert_eq(
        canonical_bytes32_to_field([
            29, 166, 198, 14, 30, 196, 97, 209, 14, 151, 184, 14, 149, 255, 32, 75,
            121, 145, 231, 47, 190, 28, 210, 139, 197, 201, 247, 132, 244, 191, 227, 102,
        ]),
        0x1da6c60e1ec461d10e97b80e95ff204b7991e72fbe1cd28bc5c9f784f4bfe366,
    );
}
